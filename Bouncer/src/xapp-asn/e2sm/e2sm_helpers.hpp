/*
# ==================================================================================
# Copyright (c) 2020 HCL Technologies Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==================================================================================
*/


/* Classes to handle E2 service model based on e2sm-Bouncer-v001.asn */
#ifndef E2SM_HELPER_
#define E2SM_HELPER_

#include <unordered_map>

extern "C" {
	#include "E2SM-RC-IndicationHeader.h"
	#include "E2SM-RC-ControlHeader.h"
	#include "E2SM-RC-ControlMessage.h"
	#include "RICindicationHeader.h"
	#include "UEID.h"
	#include "E2SM-KPM-ActionDefinition.h"
}

typedef struct e2sm_kpm_subscription_helper {
	struct {
		unsigned long reportingPeriod;
	} trigger;
	struct {
		unsigned long granulPeriod;
		E2SM_KPM_ActionDefinition__actionDefinition_formats_PR format;
	} action;
} e2sm_kpm_subscription_helper;

typedef struct e2sm_kpm_indication_fmt1_helper {
	struct {
		uint64_t timestamp;
	} header;
	struct {
		std::unordered_map<std::string, long> measurements; // measName, measRecord
	} msg;
} e2sm_kpm_indication_fmt1_helper;

typedef struct e2sm_indication_helper {
	long int header;
	unsigned char* message;
	size_t message_len;
} e2sm_indication_helper;

 typedef struct e2sm_control_helper {
	long int header;
	unsigned char* message;
	size_t message_len;
} e2sm_control_helper;

typedef enum e2sm_rc_control_action_PR {
	CONTROL_ACTION_PR_UE_ADMISSION_CONTROL,
	CONTROL_ACTION_PR_SLICE_LEVEL_PRB_QUOTA
} e2sm_rc_control_action_PR;

typedef struct e2sm_rc_slice_level_prb_quota_helper {
	long max_prb;
	long min_prb;
} e2sm_rc_slice_level_prb_quota_helper;

typedef struct e2sm_rc_control_helper {
	e2sm_rc_control_action_PR present;
	union control_action_u {
		e2sm_rc_slice_level_prb_quota_helper *prb_quota_helper;
		/* This type is extensible */
	} choice;
} e2sm_rc_control_helper;

class RCIndicationlHelper {
	public:

	E2SM_RC_IndicationHeader_t *decode_e2sm_rc_indication_header(RICindicationHeader_t *e2ap_header) {
		E2SM_RC_IndicationHeader_t *header = NULL;
		asn_transfer_syntax syntax = ATS_ALIGNED_BASIC_PER;
		asn_dec_rval_t rval = asn_decode(NULL, syntax, &asn_DEF_E2SM_RC_IndicationHeader, (void **)&header, e2ap_header->buf, e2ap_header->size);
		if (rval.code != RC_OK) {
			fprintf(stderr, "ERROR %s:%d unable to decode RC_IndicationHeader\n", __FILE__, __LINE__);
			return nullptr;
		}
		return header;
	}
};

#endif
