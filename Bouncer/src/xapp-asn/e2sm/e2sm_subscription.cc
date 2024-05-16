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

#include <sstream>
#include <vector>

#include "e2sm_subscription.hpp"

//initialize
e2sm_subscription::e2sm_subscription(void){

  kpm_trigger_def = (E2SM_KPM_EventTriggerDefinition_t *) calloc(1, sizeof(E2SM_KPM_EventTriggerDefinition_t));
  kpm_action_def = (E2SM_KPM_ActionDefinition_t *) calloc(1, sizeof(E2SM_KPM_ActionDefinition_t));

  errbuf_len = 128;
};

e2sm_subscription::~e2sm_subscription(void){

  mdclog_write(MDCLOG_DEBUG, "Freeing e2sm_subscription object memory");

  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_EventTriggerDefinition, kpm_trigger_def);
  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_ActionDefinition, kpm_action_def);

};

bool e2sm_subscription::encodeKPMTriggerDefinition(unsigned char *buffer, ssize_t *buflen, e2sm_kpm_subscription_helper& helper) {
  std::stringstream ss;

  if (!buffer) {
      ss << "Invalid reference for buffer to enconde KPM EventTriggerDefinition in fucntion " << __func__;
      error_string = ss.str();
      return false;
  }

  if (!set_fields(kpm_trigger_def, helper)) {
    return false;
  }

  char errbuf[4096] = {0,};
  size_t errlen = 4096;

  if (asn_check_constraints(&asn_DEF_E2SM_KPM_EventTriggerDefinition, kpm_trigger_def, errbuf, &errlen) != 0) {
      ss << "Constraints for " << asn_DEF_E2SM_KPM_EventTriggerDefinition.name << " did not met. Reason: " << errbuf;
      error_string = ss.str();
  }

  if (mdclog_level_get() > MDCLOG_INFO) {
      asn_fprint(stderr, &asn_DEF_E2SM_KPM_EventTriggerDefinition, kpm_trigger_def);
  }

  asn_enc_rval_t rval;
  rval = asn_encode_to_buffer(0, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_EventTriggerDefinition, kpm_trigger_def, buffer, *buflen);
  if (rval.encoded == -1) {
      ss << "Serialization of " << asn_DEF_E2SM_KPM_EventTriggerDefinition.name << " failed, type=" << rval.failed_type->name;
      error_string = ss.str();
      return false;
  }
  else if (rval.encoded > *buflen) {
      ss << "Buffer of size " << *buflen << " is too small for " << asn_DEF_E2SM_KPM_EventTriggerDefinition.name << ", need " << rval.encoded;
      error_string = ss.str();
      return false;
  }

  *buflen = rval.encoded;
  return true;
}

bool e2sm_subscription::encodeKPMActionDefinition(unsigned char *buffer, ssize_t *buflen, e2sm_kpm_subscription_helper& helper) {
    std::stringstream ss;

    if (!buffer) {
        ss << "Invalid reference for buffer to enconde E2SM_KPM_ActionDefinition in function " << __func__;
        error_string = ss.str();
        return false;
    }

    if (!set_fields(kpm_action_def, helper)) {
      return false;
    }

    char errbuf[4096] = {0,};
    size_t errlen = 4096;

    if (asn_check_constraints(&asn_DEF_E2SM_KPM_ActionDefinition, kpm_action_def, errbuf, &errlen) != 0) {
        ss << "Constraints for " << asn_DEF_E2SM_KPM_ActionDefinition.name << " did not met. Reason: " << errbuf;
        error_string = ss.str();
    }

    if (mdclog_level_get() > MDCLOG_INFO) {
      asn_fprint(stderr, &asn_DEF_E2SM_KPM_ActionDefinition, kpm_action_def);
    }

    asn_enc_rval_t rval;
    rval = asn_encode_to_buffer(0, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_ActionDefinition, kpm_action_def, buffer, *buflen);
    if (rval.encoded == -1) {
        ss << "Serialization of " << asn_DEF_E2SM_KPM_ActionDefinition.name << " failed, type=" << rval.failed_type->name;
        error_string = ss.str();
        return false;
    }
    else if (rval.encoded > *buflen) {
        ss << "Buffer of size " << *buflen << " is too small for " << asn_DEF_E2SM_KPM_ActionDefinition.name << ", need " << rval.encoded;
        error_string = ss.str();
        return false;
    }

    *buflen = rval.encoded;
    return true;
}

bool e2sm_subscription::set_fields(E2SM_KPM_EventTriggerDefinition_t *trigger_def, e2sm_kpm_subscription_helper& helper) {
  if(trigger_def == NULL){
    error_string = "Invalid reference for KPM Event Trigger Definition set fields";
    return false;
  }

  // RICeventTriggerDefinition Format 1
	kpm_trigger_def->eventDefinition_formats.choice.eventDefinition_Format1 = (E2SM_KPM_EventTriggerDefinition_Format1_t *) calloc(1, sizeof(E2SM_KPM_EventTriggerDefinition_Format1_t));
	kpm_trigger_def->eventDefinition_formats.choice.eventDefinition_Format1->reportingPeriod = helper.trigger.reportingPeriod;
	kpm_trigger_def->eventDefinition_formats.present = E2SM_KPM_EventTriggerDefinition__eventDefinition_formats_PR_eventDefinition_Format1;

  return true;
}

bool e2sm_subscription::set_fields(E2SM_KPM_ActionDefinition_t *action_def, e2sm_kpm_subscription_helper& helper) {
  if(action_def == NULL){
    error_string = "Invalid reference for KPM Action Definition set fields";
    return false;
  }

  E2SM_KPM_ActionDefinition_Format1_t *actdef_fmt1;
  if (helper.action.format == E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format1) {
    // ActionDefinition Style 1
    action_def->ric_Style_Type = 1;
    action_def->actionDefinition_formats.present = E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format1;
    action_def->actionDefinition_formats.choice.actionDefinition_Format1 = (E2SM_KPM_ActionDefinition_Format1_t *) calloc(1, sizeof(E2SM_KPM_ActionDefinition_Format1_t));

    actdef_fmt1 = action_def->actionDefinition_formats.choice.actionDefinition_Format1;

  } else if (helper.action.format == E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format4) {
    // ActionDefinition Style 4
    action_def->ric_Style_Type = 4;
    action_def->actionDefinition_formats.present = E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format4;
    action_def->actionDefinition_formats.choice.actionDefinition_Format4 = (E2SM_KPM_ActionDefinition_Format4_t *) calloc(1, sizeof(E2SM_KPM_ActionDefinition_Format4_t));

    actdef_fmt1 = &action_def->actionDefinition_formats.choice.actionDefinition_Format4->subscriptionInfo;

    // Matching Condition
    MatchingUeCondPerSubItem_t *match = (MatchingUeCondPerSubItem_t *) calloc(1, sizeof(MatchingUeCondPerSubItem_t));
    match->testCondInfo.testType.present = TestCond_Type_PR_rSRP;
    match->testCondInfo.testType.choice.rSRP = TestCond_Type__rSRP_true;
    // match->testCondInfo.testType.present = TestCond_Type_PR_fiveQI;
    // match->testCondInfo.testType.choice.sNSSAI = TestCond_Type__fiveQI_true;

    match->testCondInfo.testExpr = (TestCond_Expression_t *) calloc(1, sizeof(TestCond_Expression_t));
    *match->testCondInfo.testExpr = TestCond_Expression_present;
    // *match->testCondInfo.testExpr = TestCond_Expression_greaterthan;

    match->testCondInfo.testValue = (struct TestCond_Value *) calloc(1, sizeof(struct TestCond_Value));
    match->testCondInfo.testValue->present = TestCond_Value_PR_valueBool;
    match->testCondInfo.testValue->choice.valueBool = 1;
    // match->testCondInfo.testValue->present = TestCond_Value_PR_valueInt;
    // match->testCondInfo.testValue->choice.valueInt = 0;

    // match->logicalOR = (LogicalOR_t *) calloc(1, sizeof(LogicalOR_t));
    // *match->logicalOR = LogicalOR_true;


    ASN_SEQUENCE_ADD(&action_def->actionDefinition_formats.choice.actionDefinition_Format4->matchingUeCondList.list, match);

  } else {
    error_string = "Only ActionDefinition formats 1 and 4 are supported.";
    return false;
  }

	actdef_fmt1->granulPeriod = helper.action.granulPeriod;

	// Measurements
  std::vector<std::string> measurements = {"RSRP", "RSRQ", "CQI", "DRB.RlcPacketDropRateDl", "DRB.RlcSduTransmittedVolumeDL", "DRB.RlcSduTransmittedVolumeUL"};
  for (std::string meas : measurements) {
    MeasurementInfoItem_t *minfo = (MeasurementInfoItem_t *) calloc(1, sizeof(MeasurementInfoItem_t));
    minfo->measType.present = MeasurementType_PR_measName;
    // OCTET_STRING_t *meas_name = OCTET_STRING_new_fromBuf(&asn_DEF_MeasurementTypeName, "RSRP", 4);
    OCTET_STRING_t *meas_name = OCTET_STRING_new_fromBuf(&asn_DEF_MeasurementTypeName, meas.c_str(), meas.length());
    memcpy(&minfo->measType.choice.measName, meas_name, sizeof(OCTET_STRING_t));
    free(meas_name);
    LabelInfoItem_t *linfo = (LabelInfoItem_t *) calloc(1, sizeof(LabelInfoItem_t));
    linfo->measLabel.noLabel = (long *) calloc(1, sizeof(long));
    ASN_SEQUENCE_ADD(&minfo->labelInfoList.list, linfo);

    ASN_SEQUENCE_ADD(&actdef_fmt1->measInfoList.list, minfo);
  }

  return true;
}
