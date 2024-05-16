/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2SM-RC-IEs"
 * 	found in "defs/E2SM-RC-R003-v03.00.asn1"
 * 	`asn1c -fcompound-names -findirect-choice -fincludes-quoted -fno-include-deps -gen-PER -no-gen-OER -no-gen-example`
 */

#ifndef	_E2SM_RC_EventTrigger_Format3_Item_H_
#define	_E2SM_RC_EventTrigger_Format3_Item_H_


#include "asn_application.h"

/* Including external dependencies */
#include "RIC-EventTriggerCondition-ID.h"
#include "NativeInteger.h"
#include "LogicalOR.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct EventTrigger_Cell_Info;

/* E2SM-RC-EventTrigger-Format3-Item */
typedef struct E2SM_RC_EventTrigger_Format3_Item {
	RIC_EventTriggerCondition_ID_t	 ric_eventTriggerCondition_ID;
	long	 e2NodeInfoChange_ID;
	struct EventTrigger_Cell_Info	*associatedCellInfo;	/* OPTIONAL */
	LogicalOR_t	*logicalOR;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} E2SM_RC_EventTrigger_Format3_Item_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_E2SM_RC_EventTrigger_Format3_Item;
extern asn_SEQUENCE_specifics_t asn_SPC_E2SM_RC_EventTrigger_Format3_Item_specs_1;
extern asn_TYPE_member_t asn_MBR_E2SM_RC_EventTrigger_Format3_Item_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _E2SM_RC_EventTrigger_Format3_Item_H_ */
#include "asn_internal.h"