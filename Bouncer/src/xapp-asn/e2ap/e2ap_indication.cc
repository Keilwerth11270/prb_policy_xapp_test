/*
==================================================================================

        Copyright (c) 2019-2020 AT&T Intellectual Property.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
==================================================================================
*/
/*
 * ric_indication.c
 *
 *  Created on: Jul 11, 2019
 *      Author: sjana, Ashwin Sridharan
 */

#include "e2ap_indication.hpp"

// Set up memory allocations for each IE for encoding
// We are responsible for memory management for each IE for encoding
// Hence destructor should clear out memory
// When decoding, we rely on asn1c macro (ASN_STRUCT_FREE to be called
// for releasing memory by external calling function)
ric_indication::ric_indication(void){

  e2ap_pdu_obj = (E2AP_PDU_t * )calloc(1, sizeof(E2AP_PDU_t));
  assert(e2ap_pdu_obj != 0);

  initMsg = NULL;
  IE_array = NULL;
};



// Clear assigned protocolIE list from RIC indication IE container
ric_indication::~ric_indication(void){
  mdclog_write(MDCLOG_DEBUG, "Freeing E2AP Indication object memory");

  if (IE_array != NULL)
    free(IE_array);

  ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, e2ap_pdu_obj);

  mdclog_write(MDCLOG_DEBUG, "Freed E2AP Indication object memory");
}


bool ric_indication::encode_e2ap_indication(unsigned char *buf, ssize_t *size, ric_indication_helper & dinput){
  initMsg = (InitiatingMessage_t * )calloc(1, sizeof(InitiatingMessage_t));
  assert(initMsg != 0);

  e2ap_pdu_obj->present = E2AP_PDU_PR_initiatingMessage;
  e2ap_pdu_obj->choice.initiatingMessage = initMsg;

  initMsg->procedureCode = ProcedureCode_id_RICindication;
  initMsg->criticality = Criticality_ignore;
  initMsg->value.present = InitiatingMessage__value_PR_RICindication;

  bool res;
  asn_enc_rval_t retval;

  res = set_fields(initMsg, dinput);
  if (!res){
    return false;
  }

  int ret_constr = asn_check_constraints(&asn_DEF_E2AP_PDU, e2ap_pdu_obj, errbuf, &errbuf_len);
  if(ret_constr){
    error_string.assign(&errbuf[0], errbuf_len);
    error_string = "Error encoding E2AP Indication message. Reason = " + error_string;
    return false;
  }

  // std::cout <<"Constraint check ok ...." << std::endl;
  // xer_fprint(stdout, &asn_DEF_E2AP_PDU, e2ap_pdu_obj);

  retval = asn_encode_to_buffer(0, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2AP_PDU, e2ap_pdu_obj, buf, *size);
  if(retval.encoded == -1){
    error_string.assign(strerror(errno));
    return false;
  }

  else {
    if(*size < retval.encoded){
      std::stringstream ss;
      ss  <<"Error encoding E2AP Indication . Reason =  encoded pdu size " << retval.encoded << " exceeds buffer size " << *size << std::endl;
      error_string = ss.str();
      return false;
    }
  }

  *size = retval.encoded;
  return true;

}

bool ric_indication::decode_e2ap_indication(unsigned char *buf, ssize_t size, ric_indication_helper & doutput) {
  asn_transfer_syntax syntax = ATS_ALIGNED_BASIC_PER;

  ASN_STRUCT_RESET(asn_DEF_E2AP_PDU, e2ap_pdu_obj);

  auto rval = asn_decode(nullptr, syntax, &asn_DEF_E2AP_PDU, (void **)&e2ap_pdu_obj, buf, size);

  mdclog_write(MDCLOG_DEBUG, "%s:%d: rval.code = %d, rval.consumed = %lu", __func__, __LINE__, rval.code, rval.consumed);

  if (rval.code != RC_OK) {
    mdclog_write(MDCLOG_ERR, "Decoding error on E2AP Indication. Next is the partially decoded E2AP_PDU"); // we consider RC_WMORE as error
    asn_fprint(stderr, &asn_DEF_E2AP_PDU, e2ap_pdu_obj);
    std::stringstream ss;
    ss << "rval.code=" << rval.code << " rval.consumed=" << rval.consumed;
    error_string = ss.str();
    return false;
  }

  if (mdclog_level_get() > MDCLOG_INFO)
    asn_fprint(stderr, &asn_DEF_E2AP_PDU, e2ap_pdu_obj);

  if (!get_fields(e2ap_pdu_obj->choice.initiatingMessage, doutput)) {
    return false;
  }

  return true;
}

bool ric_indication::set_fields(InitiatingMessage_t *initMsg, ric_indication_helper &dinput){
  unsigned int ie_index;

  if (initMsg == 0){
    error_string = "Invalid reference for E2AP Indication message in set_fields";
    return false;
  }

  IE_array = (RICindication_IEs_t *)calloc(NUM_INDICATION_IES, sizeof(RICindication_IEs_t));
  assert(IE_array != 0);

  RICindication_t * ric_indication = &(initMsg->value.choice.RICindication);
  ric_indication->protocolIEs.list.count = 0;

  ie_index = 0;

  RICindication_IEs_t *ies_ricreq = &IE_array[ie_index];
  ies_ricreq->criticality = Criticality_reject;
  ies_ricreq->id = ProtocolIE_ID_id_RICrequestID;
  ies_ricreq->value.present = RICindication_IEs__value_PR_RICrequestID;
  RICrequestID_t *ricrequest_ie = &ies_ricreq->value.choice.RICrequestID;
  ricrequest_ie->ricRequestorID = dinput.request_id.ricRequestorID;
  ricrequest_ie->ricInstanceID = dinput.request_id.ricInstanceID;
  ASN_SEQUENCE_ADD(&(ric_indication->protocolIEs), &(IE_array[ie_index]));

  ie_index = 1;
  RICindication_IEs_t *ies_ranfunc = &IE_array[ie_index];
  ies_ranfunc->criticality = Criticality_reject;
  ies_ranfunc->id = ProtocolIE_ID_id_RANfunctionID;
  ies_ranfunc->value.present = RICindication_IEs__value_PR_RANfunctionID;
  RANfunctionID_t *ranfunction_ie = &ies_ranfunc->value.choice.RANfunctionID;
  *ranfunction_ie = dinput.func_id;
  ASN_SEQUENCE_ADD(&(ric_indication->protocolIEs), &(IE_array[ie_index]));

  ie_index = 2;
  RICindication_IEs_t *ies_actid = &IE_array[ie_index];
  ies_actid->criticality = Criticality_reject;
  ies_actid->id = ProtocolIE_ID_id_RICactionID;
  ies_actid->value.present = RICindication_IEs__value_PR_RICactionID;
  RICactionID_t *ricaction_ie = &ies_actid->value.choice.RICactionID;
  *ricaction_ie = dinput.action_id;
  ASN_SEQUENCE_ADD(&(ric_indication->protocolIEs), &(IE_array[ie_index]));

  ie_index = 3;
  RICindication_IEs_t *ies_ricsn = &IE_array[ie_index];
  ies_ricsn->criticality = Criticality_reject;
  ies_ricsn->id = ProtocolIE_ID_id_RICindicationSN;
  ies_ricsn->value.present = RICindication_IEs__value_PR_RICindicationSN;
  RICindicationSN_t *ricsn_ie = &ies_ricsn->value.choice.RICindicationSN;
  *ricsn_ie = dinput.indication_sn;
  ASN_SEQUENCE_ADD(&(ric_indication->protocolIEs), &(IE_array[ie_index]));


  ie_index = 4;
  RICindication_IEs_t *ies_indtyp = &IE_array[ie_index];
  ies_indtyp->criticality = Criticality_reject;
  ies_indtyp->id = ProtocolIE_ID_id_RICindicationType;
  ies_indtyp->value.present = RICindication_IEs__value_PR_RICindicationType;
  RICindicationType_t *rictype_ie = &ies_indtyp->value.choice.RICindicationType;
  *rictype_ie = dinput.indication_type;
  ASN_SEQUENCE_ADD(&(ric_indication->protocolIEs), &(IE_array[ie_index]));

  ie_index = 5;
  RICindication_IEs_t *ies_richead = &IE_array[ie_index];
  ies_richead->criticality = Criticality_reject;
  ies_richead->id = ProtocolIE_ID_id_RICindicationHeader;
  ies_richead->value.present = RICindication_IEs__value_PR_RICindicationHeader;
  RICindicationHeader_t *richeader_ie = &ies_richead->value.choice.RICindicationHeader;
  richeader_ie->buf = dinput.indication_header.buf;
  richeader_ie->size = dinput.indication_header.size;
  ASN_SEQUENCE_ADD(&(ric_indication->protocolIEs), &(IE_array[ie_index]));

  ie_index = 6;
  RICindication_IEs_t *ies_indmsg = &IE_array[ie_index];
  ies_indmsg->criticality = Criticality_reject;
  ies_indmsg->id = ProtocolIE_ID_id_RICindicationMessage;
  ies_indmsg->value.present = RICindication_IEs__value_PR_RICindicationMessage;
  RICindicationMessage_t *ricmsg_ie = &ies_indmsg->value.choice.RICindicationMessage;
  ricmsg_ie->buf = dinput.indication_msg.buf;
  ricmsg_ie->size = dinput.indication_msg.size;
  ASN_SEQUENCE_ADD(&(ric_indication->protocolIEs), &(IE_array[ie_index]));


  // optional call process id ..
  if (dinput.call_process_id.size > 0){
    ie_index = 7;
    RICindication_IEs_t *ies_ind_callprocessid = &IE_array[ie_index];
    ies_ind_callprocessid->criticality = Criticality_reject;
    ies_ind_callprocessid->id = ProtocolIE_ID_id_RICcallProcessID;
    ies_ind_callprocessid->value.present = RICindication_IEs__value_PR_RICcallProcessID;
    RICcallProcessID_t *riccallprocessid_ie = &ies_ind_callprocessid->value.choice.RICcallProcessID;
    riccallprocessid_ie->buf = dinput.call_process_id.buf;
    riccallprocessid_ie->size = dinput.call_process_id.size;
    ASN_SEQUENCE_ADD(&(ric_indication->protocolIEs), &(IE_array[ie_index]));
  }

  return true;

};




bool ric_indication:: get_fields(InitiatingMessage_t * init_msg,  ric_indication_helper &dout)
{
  if (init_msg == 0){
    error_string = "Invalid reference for E2AP Indication message in get_fields";
    return false;
  }


  for(int edx = 0; edx < init_msg->value.choice.RICindication.protocolIEs.list.count; edx++) {
    RICindication_IEs_t *memb_ptr = init_msg->value.choice.RICindication.protocolIEs.list.array[edx];

    switch (memb_ptr->id)
    {
      case (ProtocolIE_ID_id_RICindicationHeader):
        dout.indication_header = memb_ptr->value.choice.RICindicationHeader;
        break;

      case (ProtocolIE_ID_id_RICindicationMessage):
        dout.indication_msg = memb_ptr->value.choice.RICindicationMessage;
        break;

      case (ProtocolIE_ID_id_RICrequestID):
        dout.request_id = memb_ptr->value.choice.RICrequestID;
        break;

      case (ProtocolIE_ID_id_RANfunctionID):
        dout.func_id = memb_ptr->value.choice.RANfunctionID;
        break;

      case (ProtocolIE_ID_id_RICindicationSN):
        dout.indication_sn = memb_ptr->value.choice.RICindicationSN;
        break;

      case (ProtocolIE_ID_id_RICindicationType):
        dout.indication_type = memb_ptr->value.choice.RICindicationType;
        break;

      case (ProtocolIE_ID_id_RICactionID):
        dout.action_id = memb_ptr->value.choice.RICactionID;
        break;

      case (ProtocolIE_ID_id_RICcallProcessID):
        dout.call_process_id = memb_ptr->value.choice.RICcallProcessID;
        break;

      default:
        break;
    }
  }

  return true;

}

InitiatingMessage_t * ric_indication::get_message(void)  {
    return initMsg;
}
