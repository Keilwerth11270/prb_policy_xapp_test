/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2AP-PDU-Contents"
 * 	found in "defs/E2AP-R003-v03.00.asn1"
 * 	`asn1c -fcompound-names -findirect-choice -fincludes-quoted -fno-include-deps -gen-PER -no-gen-OER -no-gen-example`
 */

#include "RICactions-ToBeRemovedForModification-List.h"

#include "ProtocolIE-SingleContainer.h"
static asn_per_constraints_t asn_PER_type_RICactions_ToBeRemovedForModification_List_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 5,  5,  0,  16 }	/* (SIZE(0..16)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_RICactions_ToBeRemovedForModification_List_1[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_ProtocolIE_SingleContainer_2532P4,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_RICactions_ToBeRemovedForModification_List_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_RICactions_ToBeRemovedForModification_List_specs_1 = {
	sizeof(struct RICactions_ToBeRemovedForModification_List),
	offsetof(struct RICactions_ToBeRemovedForModification_List, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t asn_DEF_RICactions_ToBeRemovedForModification_List = {
	"RICactions-ToBeRemovedForModification-List",
	"RICactions-ToBeRemovedForModification-List",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_RICactions_ToBeRemovedForModification_List_tags_1,
	sizeof(asn_DEF_RICactions_ToBeRemovedForModification_List_tags_1)
		/sizeof(asn_DEF_RICactions_ToBeRemovedForModification_List_tags_1[0]), /* 1 */
	asn_DEF_RICactions_ToBeRemovedForModification_List_tags_1,	/* Same as above */
	sizeof(asn_DEF_RICactions_ToBeRemovedForModification_List_tags_1)
		/sizeof(asn_DEF_RICactions_ToBeRemovedForModification_List_tags_1[0]), /* 1 */
	{ 0, &asn_PER_type_RICactions_ToBeRemovedForModification_List_constr_1, SEQUENCE_OF_constraint },
	asn_MBR_RICactions_ToBeRemovedForModification_List_1,
	1,	/* Single element */
	&asn_SPC_RICactions_ToBeRemovedForModification_List_specs_1	/* Additional specs */
};

