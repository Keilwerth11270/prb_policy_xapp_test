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
#include "e2sm_indication.hpp"

extern "C" {
  #include "E2SM-KPM-IndicationHeader-Format1.h"
  #include "E2SM-KPM-IndicationMessage-Format1.h"
  #include "MeasurementInfoList.h"
  #include "MeasurementInfoItem.h"
  #include "MeasurementDataItem.h"
  #include "MeasurementRecordItem.h"
}

//initialize
e2sm_indication::e2sm_indication(void){

  indication_head = NULL;
  indication_msg = NULL;

  kpm_header = NULL;
  kpm_msg = NULL;

  errbuf_len = 128;
};

e2sm_indication::~e2sm_indication(void){

  mdclog_write(MDCLOG_DEBUG, "Freeing e2sm_indication object memory");

  if (indication_head != NULL)
    ASN_STRUCT_FREE(asn_DEF_E2SM_Bouncer_IndicationHeader, indication_head);

  if (indication_msg != NULL)
    ASN_STRUCT_FREE(asn_DEF_E2SM_Bouncer_IndicationMessage, indication_msg);

  if (kpm_header != NULL)
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationHeader, kpm_header);

  if (kpm_msg != NULL)
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, kpm_msg);

}

bool e2sm_indication::encode_bouncer_indication_header(unsigned char *buf, ssize_t *size, e2sm_indication_helper &helper){

  indication_head = ( E2SM_Bouncer_IndicationHeader_t *)calloc(1, sizeof( E2SM_Bouncer_IndicationHeader_t));
  assert(indication_head != 0);

  bool res = set_fields(indication_head, helper);
  if (!res){
    return false;
  }

  int ret_constr = asn_check_constraints(&asn_DEF_E2SM_Bouncer_IndicationHeader, indication_head, errbuf, &errbuf_len);
  if(ret_constr){
    error_string.assign(&errbuf[0], errbuf_len);
    return false;
  }

  if (mdclog_level_get() > MDCLOG_INFO) {
    xer_fprint(stderr, &asn_DEF_E2SM_Bouncer_IndicationHeader, indication_head);
  }

  asn_enc_rval_t retval = asn_encode_to_buffer(0, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_Bouncer_IndicationHeader, indication_head, buf, *size);

  if(retval.encoded == -1){
    error_string.assign(strerror(errno));
    return false;
  }
  else if (retval.encoded > *size){
    std::stringstream ss;
    ss  <<"Error encoding E2SM_Bouncer_IndicationHeader_Format1 event trigger definition. Reason =  encoded pdu size " << retval.encoded << " exceeds buffer size " << *size << std::endl;
    error_string = ss.str();
    return false;
  }
  else{
    *size = retval.encoded;
  }

  return true;
}

bool e2sm_indication::encode_bouncer_indication_message(unsigned char *buf, ssize_t *size, e2sm_indication_helper &helper){
  indication_msg = (E2SM_Bouncer_IndicationMessage_t*)calloc(1, sizeof(E2SM_Bouncer_IndicationMessage_t));
  assert(indication_msg !=0);

  bool res = set_fields(indication_msg, helper);
  if (!res){
    return false;
  }


  int ret_constr = asn_check_constraints(&asn_DEF_E2SM_Bouncer_IndicationMessage, indication_msg, errbuf, &errbuf_len);
  if(ret_constr){
    error_string.assign(&errbuf[0], errbuf_len);
    return false;
  }

  if (mdclog_level_get() > MDCLOG_INFO) {
    xer_fprint(stderr, &asn_DEF_E2SM_Bouncer_IndicationMessage, indication_msg);
  }

  asn_enc_rval_t retval = asn_encode_to_buffer(0, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_Bouncer_IndicationMessage, indication_msg, buf, *size);

  if(retval.encoded == -1){
    error_string.assign(strerror(errno));
    return false;
  }
  else if (retval.encoded > *size){
    std::stringstream ss;
    ss  <<"Error encoding action definition. Reason =  encoded pdu size " << retval.encoded << " exceeds buffer size " << *size << std::endl;
    error_string = ss.str();
    return false;
  }
  else{
    *size = retval.encoded;
  }

  return true;
}

bool e2sm_indication::set_fields(E2SM_Bouncer_IndicationHeader_t * ref_indication_head, e2sm_indication_helper & helper){

 if(ref_indication_head == 0){
    error_string = "Invalid reference for E2SM_Bouncer_IndicationHeader_t set fields";
    return false;
  }

  ref_indication_head->present = E2SM_Bouncer_IndicationHeader_PR_indicationHeader_Format1;

  ref_indication_head->choice.indicationHeader_Format1 = (E2SM_Bouncer_IndicationHeader_Format1_t * ) calloc(1, sizeof(E2SM_Bouncer_IndicationHeader_Format1_t));

  ref_indication_head->choice.indicationHeader_Format1->indicationHeaderParam = helper.header;

  return true;
};

bool e2sm_indication::set_fields(E2SM_Bouncer_IndicationMessage_t * ref_indication_msg, e2sm_indication_helper & helper){

 if(ref_indication_msg == 0){
    error_string = "Invalid reference for E2SM_Bouncer_IndicationMessage_t set fields";
    return false;
  }
  ref_indication_msg->present = E2SM_Bouncer_IndicationMessage_PR_indicationMessage_Format1;

  ref_indication_msg->choice.indicationMessage_Format1 = (E2SM_Bouncer_IndicationMessage_Format1_t *) calloc(1, sizeof(E2SM_Bouncer_IndicationMessage_Format1_t));

  ref_indication_msg->choice.indicationMessage_Format1->indicationMsgParam.buf = helper.message;
  ref_indication_msg->choice.indicationMessage_Format1->indicationMsgParam.size = helper.message_len;

  return true;
}

bool e2sm_indication::get_fields(E2SM_Bouncer_IndicationHeader_t * ref_indictaion_header, e2sm_indication_helper & helper){

	if (ref_indictaion_header == 0){
	    error_string = "Invalid reference for Indication Header get fields";
	    return false;
	  }

	helper.header = ref_indictaion_header->choice.indicationHeader_Format1->indicationHeaderParam;
	return true;
}

bool e2sm_indication::get_fields(E2SM_Bouncer_IndicationMessage_t * ref_indication_message, e2sm_indication_helper & helper){

  if (ref_indication_message == 0){
    error_string = "Invalid reference for Indication Message get fields";
    return false;
  }
  helper.message = ref_indication_message->choice.indicationMessage_Format1->indicationMsgParam.buf;
  helper.message_len = ref_indication_message->choice.indicationMessage_Format1->indicationMsgParam.size;

  return true;
}

bool e2sm_indication::decode_kpm_indication_header_format1(RICindicationHeader_t *header, e2sm_kpm_indication_fmt1_helper &helper) {
  int count = 0;
  uint8_t *bufptr = header->buf;
  size_t len = header->size;

  asn_dec_rval_t rval;
  do {  // FIXME asn_decode always returns RC_WMORE and rval.consumed=0 bytes
    rval = asn_decode(NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationHeader, (void **)&kpm_header, bufptr, len);
    mdclog_write(MDCLOG_DEBUG, "%s:%d: asn_decode returned rval.code=%d, rval.consumed=%lu", __func__, __LINE__, rval.code, rval.consumed);

    if (rval.code == RC_WMORE) {
      count++;
      if(count == 10) {
        error_string = "Too many counts...";
        return false;
      }

      bufptr += rval.consumed;
      len -= rval.consumed;
    }

  } while(rval.code == RC_WMORE || count < 10);

  if (rval.code == RC_FAIL) {
    error_string = "Unable to decode E2SM_KPM_IndicationHeader";
    return false;
  }

  TimeStamp_t *time = &kpm_header->indicationHeader_formats.choice.indicationHeader_Format1->colletStartTime;
  if (time->size != 8) {
    error_string = "Unable to decode colletStartTime in E2SM_KPM_IndicationHeader. Reason: size is not 8";
    return false;
  }
  memcpy(&helper.header.timestamp, time->buf, time->size);

  return true;
}

bool e2sm_indication::decode_kpm_indication_msg_format1(RICindicationMessage_t *msg, e2sm_kpm_indication_fmt1_helper &helper) {
  asn_dec_rval_t rval = asn_decode(NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationMessage, (void **)&kpm_msg, msg->buf, msg->size);
  if (rval.code != RC_OK) {
    error_string = "Unable to decode E2SM_KPM_IndicationMessage";
    return false;
  }

  int len = kpm_msg->indicationMessage_formats.choice.indicationMessage_Format1->measInfoList->list.count;
  if (kpm_msg->indicationMessage_formats.choice.indicationMessage_Format1->measData.list.count != 1) {
    error_string = "The number of elements in measData list is not 1";
    return false;
  }

  MeasurementDataItem_t **dataItems = kpm_msg->indicationMessage_formats.choice.indicationMessage_Format1->measData.list.array;
  MeasurementDataItem_t *dataItem = dataItems[0];

  if (len != dataItem->measRecord.list.count) {
    error_string = "The number of elements in measRecord and measInfoList is not equal";
    return false;
  }

  MeasurementInfoItem_t **infoItems = kpm_msg->indicationMessage_formats.choice.indicationMessage_Format1->measInfoList->list.array;
  MeasurementRecordItem_t **records = dataItem->measRecord.list.array;

  for (int i = 0; i < len; i++) {
    MeasurementInfoItem_t *info = infoItems[i];
    MeasurementRecordItem_t *data = records[i];

    std::string name((char *)info->measType.choice.measName.buf, info->measType.choice.measName.size);
    long value;
    memcpy(&value, &data->choice.integer, sizeof(long));
    helper.msg.measurements.emplace(name, value);
  }

  return true;
}
