package ikemsg

import "strconv"

// notifyNames are the IANA "IKEv2 Notify Message Types" this package can
// name: the error types, and the status types it meets in practice.
var notifyNames = map[NotifyType]string{
	1:     "UNSUPPORTED_CRITICAL_PAYLOAD",
	4:     "INVALID_IKE_SPI",
	5:     "INVALID_MAJOR_VERSION",
	7:     "INVALID_SYNTAX",
	9:     "INVALID_MESSAGE_ID",
	11:    "INVALID_SPI",
	14:    "NO_PROPOSAL_CHOSEN",
	17:    "INVALID_KE_PAYLOAD",
	24:    "AUTHENTICATION_FAILED",
	34:    "SINGLE_PAIR_REQUIRED",
	35:    "NO_ADDITIONAL_SAS",
	36:    "INTERNAL_ADDRESS_FAILURE",
	37:    "FAILED_CP_REQUIRED",
	38:    "TS_UNACCEPTABLE",
	39:    "INVALID_SELECTORS",
	40:    "UNACCEPTABLE_ADDRESSES",
	41:    "UNEXPECTED_NAT_DETECTED",
	43:    "TEMPORARY_FAILURE",
	44:    "CHILD_SA_NOT_FOUND",
	46:    "AUTHORIZATION_FAILED",
	16384: "INITIAL_CONTACT",
	16385: "SET_WINDOW_SIZE",
	16386: "ADDITIONAL_TS_POSSIBLE",
	16387: "IPCOMP_SUPPORTED",
	16388: "NAT_DETECTION_SOURCE_IP",
	16389: "NAT_DETECTION_DESTINATION_IP",
	16390: "COOKIE",
	16391: "USE_TRANSPORT_MODE",
	16393: "REKEY_SA",
	16394: "ESP_TFC_PADDING_NOT_SUPPORTED",
	16395: "NON_FIRST_FRAGMENTS_ALSO",
	16396: "MOBIKE_SUPPORTED",
	16430: "IKEV2_FRAGMENTATION_SUPPORTED",
	16431: "SIGNATURE_HASH_ALGORITHMS",
}

// String returns the IANA name of a notify type, or its number when unknown.
func (t NotifyType) String() string {
	if name, ok := notifyNames[t]; ok {
		return name
	}
	return strconv.Itoa(int(t))
}
