/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"bytes"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
)

func (msp *bccspmsp) validateIdentity(id *identity) error {
	id.validationMutex.Lock()
	defer id.validationMutex.Unlock()

	// return cached validation value if already validated
	if id.validated {
		return id.validationErr
	}

	id.validated = true
	if id == nil {
		return errors.New("Invalid bccsp identity. Must be different from nil.")
	}
	validationChain, err := bccsp.GetValidationChain(msp.opts, msp.certificationTreeInternalNodesMap, id.cert, false)
	if err != nil {
		id.validationErr = errors.WithMessage(err, "could not obtain certification chain")
		mspLogger.Warnf("Could not validate identity: %s (certificate subject=%s issuer=%s serialnumber=%d)", id.validationErr, id.cert.Subject, id.cert.Issuer, id.cert.SerialNumber)
		return id.validationErr
	}

	err = bccsp.ValidateCertAgainstChain(id.cert.Cert(), validationChain, msp.CRL)
	if err != nil {
		id.validationErr = errors.WithMessage(err, "could not validate identity against certification chain")
		mspLogger.Warnf("Could not validate identity: %s (certificate subject=%s issuer=%s serialnumber=%d)", id.validationErr, id.cert.Subject, id.cert.Issuer, id.cert.SerialNumber)
		return id.validationErr
	}

	err = msp.internalValidateIdentityOusFunc(id)
	if err != nil {
		id.validationErr = errors.WithMessage(err, "could not validate identity's OUs")
		mspLogger.Warnf("Could not validate identity: %s (certificate subject=%s issuer=%s serialnumber=%d)", id.validationErr, id.cert.Subject, id.cert.Issuer, id.cert.SerialNumber)
		return id.validationErr
	}

	return nil
}

func (msp *bccspmsp) validateCAIdentity(id *identity) error {
	if !id.cert.IsCA() {
		return errors.New("Only CA identities can be validated")
	}

	validationChain, err := bccsp.GetUniqueValidationChain(id.cert.Cert(), bccsp.GetValidityOptsForCert(msp.opts, id.cert.Cert()))
	if err != nil {
		return errors.WithMessage(err, "could not obtain certification chain")
	}
	if len(validationChain) == 1 {
		// validationChain[0] is the root CA certificate
		return nil
	}

	return bccsp.ValidateCertAgainstChain(id.cert.Cert(), validationChain, msp.CRL)
}

func (msp *bccspmsp) validateIdentityOUsV1(id *identity) error {
	// Check that the identity's OUs are compatible with those recognized by this MSP,
	// meaning that the intersection is not empty.
	if len(msp.ouIdentifiers) > 0 {
		found := false

		for _, OU := range id.GetOrganizationalUnits() {
			certificationIDs, exists := msp.ouIdentifiers[OU.OrganizationalUnitIdentifier]

			if exists {
				for _, certificationID := range certificationIDs {
					if bytes.Equal(certificationID, OU.CertifiersIdentifier) {
						found = true
						break
					}
				}
			}
		}

		if !found {
			if len(id.GetOrganizationalUnits()) == 0 {
				return errors.New("the identity certificate does not contain an Organizational Unit (OU)")
			}
			return errors.Errorf("none of the identity's organizational units %s are in MSP %s", OUIDs(id.GetOrganizationalUnits()), msp.name)
		}
	}

	return nil
}

func (msp *bccspmsp) validateIdentityOUsV11(id *identity) error {
	// Run the same checks as per V1
	err := msp.validateIdentityOUsV1(id)
	if err != nil {
		return err
	}

	// Perform V1_1 additional checks:
	//
	// -- Check for OU enforcement
	if !msp.ouEnforcement {
		// No enforcement required
		return nil
	}

	// Make sure that the identity has only one of the special OUs
	// used to tell apart clients or peers.
	counter := 0
	for _, OU := range id.GetOrganizationalUnits() {
		// Is OU.OrganizationalUnitIdentifier one of the special OUs?
		var nodeOU *OUIdentifier
		switch OU.OrganizationalUnitIdentifier {
		case msp.clientOU.OrganizationalUnitIdentifier:
			nodeOU = msp.clientOU
		case msp.peerOU.OrganizationalUnitIdentifier:
			nodeOU = msp.peerOU
		default:
			continue
		}

		// Yes. Then, enforce the certifiers identifier is this is specified.
		// It is not specified, it means that any certification path is fine.
		if len(nodeOU.CertifiersIdentifier) != 0 && !bytes.Equal(nodeOU.CertifiersIdentifier, OU.CertifiersIdentifier) {
			return errors.Errorf("certifiersIdentifier does not match: %v, MSP: [%s]", OUIDs(id.GetOrganizationalUnits()), msp.name)
		}
		counter++
		if counter > 1 {
			break
		}
	}

	// the identity should have exactly one OU role, return an error if the counter is not 1.
	if counter == 0 {
		return errors.Errorf("the identity does not have an OU that resolves to client or peer. OUs: %s, MSP: [%s]", OUIDs(id.GetOrganizationalUnits()), msp.name)
	}
	if counter > 1 {
		return errors.Errorf("the identity must be a client or a peer identity to be valid, not a combination of them. OUs: %s, MSP: [%s]", OUIDs(id.GetOrganizationalUnits()), msp.name)
	}

	return nil
}

func (msp *bccspmsp) validateIdentityOUsV142(id *identity) error {
	// Run the same checks as per V1
	err := msp.validateIdentityOUsV1(id)
	if err != nil {
		return err
	}

	// -- Check for OU enforcement
	if !msp.ouEnforcement {
		// No enforcement required
		return nil
	}

	// Make sure that the identity has only one of the special OUs
	// used to tell apart clients, peers and admins.
	counter := 0
	validOUs := make(map[string]*OUIdentifier)
	if msp.clientOU != nil {
		validOUs[msp.clientOU.OrganizationalUnitIdentifier] = msp.clientOU
	}
	if msp.peerOU != nil {
		validOUs[msp.peerOU.OrganizationalUnitIdentifier] = msp.peerOU
	}
	if msp.adminOU != nil {
		validOUs[msp.adminOU.OrganizationalUnitIdentifier] = msp.adminOU
	}
	if msp.ordererOU != nil {
		validOUs[msp.ordererOU.OrganizationalUnitIdentifier] = msp.ordererOU
	}

	for _, OU := range id.GetOrganizationalUnits() {
		// Is OU.OrganizationalUnitIdentifier one of the special OUs?
		nodeOU := validOUs[OU.OrganizationalUnitIdentifier]
		if nodeOU == nil {
			continue
		}

		// Yes. Then, enforce the certifiers identifier in this is specified.
		// If is not specified, it means that any certification path is fine.
		if len(nodeOU.CertifiersIdentifier) != 0 && !bytes.Equal(nodeOU.CertifiersIdentifier, OU.CertifiersIdentifier) {
			return errors.Errorf("certifiersIdentifier does not match: %s, MSP: [%s]", OUIDs(id.GetOrganizationalUnits()), msp.name)
		}
		counter++
		if counter > 1 {
			break
		}
	}

	// the identity should have exactly one OU role, return an error if the counter is not 1.
	if counter == 0 {
		return errors.Errorf("the identity does not have an OU that resolves to client, peer, orderer, or admin role. OUs: %s, MSP: [%s]", OUIDs(id.GetOrganizationalUnits()), msp.name)
	}
	if counter > 1 {
		return errors.Errorf("the identity must have a client, a peer, an orderer, or an admin OU role to be valid, not a combination of them. OUs: %s, MSP: [%s]", OUIDs(id.GetOrganizationalUnits()), msp.name)
	}

	return nil
}
