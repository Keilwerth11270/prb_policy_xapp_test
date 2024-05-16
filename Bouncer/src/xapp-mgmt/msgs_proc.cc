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

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include "msgs_proc.hpp"
#include "e2sm_indication.hpp"


bool XappMsgHandler::encode_subscription_delete_request(unsigned char* buffer, ssize_t *buf_len){

	subscription_helper sub_helper;
	sub_helper.set_request({0, 0, 0}); // requirement of subscription manager ... ?
	sub_helper.set_function_id(0);

	subscription_delete e2ap_sub_req_del;

	  // generate the delete request pdu

	  bool res = e2ap_sub_req_del.encode_e2ap_subscription(&buffer[0], buf_len, sub_helper);
	  if(! res){
	    mdclog_write(MDCLOG_ERR, "%s, %d: Error encoding subscription delete request pdu. Reason = %s", __FILE__, __LINE__, e2ap_sub_req_del.get_error().c_str());
	    return false;
	  }

	return true;

}

bool XappMsgHandler::decode_subscription_response(unsigned char* data_buf, size_t data_size){

	subscription_helper subhelper;
	subscription_response subresponse;
	bool res = true;
	E2AP_PDU_t *e2pdu = 0;

	asn_dec_rval_t rval;

	ASN_STRUCT_RESET(asn_DEF_E2AP_PDU, e2pdu);

	rval = asn_decode(0,ATS_ALIGNED_BASIC_PER, &asn_DEF_E2AP_PDU, (void**)&e2pdu, data_buf, data_size);
	switch(rval.code)
	{
		case RC_OK:
			   //Put in Subscription Response Object.
			   //asn_fprint(stdout, &asn_DEF_E2AP_PDU, e2pdu);
			   break;
		case RC_WMORE:
				mdclog_write(MDCLOG_ERR, "RC_WMORE");
				res = false;
				break;
		case RC_FAIL:
				mdclog_write(MDCLOG_ERR, "RC_FAIL");
				res = false;
				break;
		default:
				break;
	 }
	ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, e2pdu);
	return res;

}

bool XappMsgHandler::a1_policy_handler(char *message, int *message_len, a1_policy_helper &helper) {
	if (! _ref_a1_handler->parse_a1_policy(message, helper)) {
		mdclog_write(MDCLOG_ERR, "Unable to process A1 policy request. Reason: %s", _ref_a1_handler->error_string.c_str());
		return false;
	}

  if (helper.policy_type_id == "20008"){
    if (helper.operation == "CREATE") {
			if (! _ref_a1_handler->parse_a1_payload(helper)) {
				mdclog_write(MDCLOG_ERR, "Unable to process A1 policy request. Reason: %s", _ref_a1_handler->error_string.c_str());
				return false;
			}

			std::stringstream ss;
			for (std::shared_ptr<ue_rc_helper> ue : helper.ue_list) {	// getting the policy payload for logging
				ss << "{ue_index:" << ue->ue_index << ", max_prb:" << ue->max_prb << "},";
			}
			mdclog_write(MDCLOG_INFO, "A1 policy request: handler_id=%s, operation=%s, policy_type_id=%s, policy_instance_id=%s, ues=%s",
						helper.handler_id.c_str(),
						helper.operation.c_str(),
						helper.policy_type_id.c_str(),
						helper.policy_instance_id.c_str(),
						ss.str().c_str());

			// TODO implement policy enforcement logic here
			e2sm_rc_control_helper control_helper;
			e2sm_rc_slice_level_prb_quota_helper quota_helper;
			control_helper.present = CONTROL_ACTION_PR_SLICE_LEVEL_PRB_QUOTA;
			control_helper.choice.prb_quota_helper = &quota_helper;

			e2sm_control control;
			for (std::shared_ptr<ue_rc_helper> ue : helper.ue_list) {	// getting the policy payload for logging
				mdclog_write(MDCLOG_INFO, "Aplying policy enforcement for %s {ue_index: %d, max_prb: %d",
						"???? meid ????", ue->ue_index, ue->max_prb);

				quota_helper.max_prb = ue->max_prb;
				quota_helper.min_prb = 1;	// dummy value as policy does not define any value here; // FIXME check if we do not need to send to srsRAN

				uint8_t ctrl_header_buf[8192] = {0, };
				ssize_t ctrl_header_buf_size = 8192;

				bool ret_head = control.encode_rc_control_header(ctrl_header_buf, &ctrl_header_buf_size, CONTROL_ACTION_PR_SLICE_LEVEL_PRB_QUOTA);
				if (!ret_head) {
					mdclog_write(MDCLOG_ERR, "Unable do encode RC control header in %s. Reason: %s", __func__, control.get_error().c_str());
					return false;
				}

				uint8_t ctrl_msg_buf[8192] = {0, };
				ssize_t ctrl_msg_buf_size = 8192;

				bool ret_msg = control.encode_rc_control_message(ctrl_msg_buf, &ctrl_msg_buf_size, &control_helper);
				if (!ret_msg) {
					mdclog_write(MDCLOG_ERR, "Unable do encode RC control message in %s. Reason: %s", __func__, control.get_error().c_str());
					return false;
				}

				// E2AP Control Helper
				ric_control_helper ric_control_helper;
				ric_control_helper.requestor_id = 123;	// dummy
				ric_control_helper.instance_id = 1;		// dummy
				ric_control_helper.func_id = 148;
				// Control Call Process ID
				ric_control_helper.call_process_id_size = 0;	// there is generated as response for a ric indication insert
				ric_control_helper.call_process_id = NULL;
				// Control ACK
				ric_control_helper.control_ack = RICcontrolAckRequest_noAck; // for now we do not require ACK messages for control requests
				// Control Header
				ric_control_helper.control_header = ctrl_header_buf;
				ric_control_helper.control_header_size = ctrl_header_buf_size;
				// Control Message
				ric_control_helper.control_msg = ctrl_msg_buf;
				ric_control_helper.control_msg_size = ctrl_msg_buf_size;

				// E2AP buffer
				uint8_t e2ap_buf[8192] = {0, };
				ssize_t e2ap_buf_size = 8192;

				ric_control_request control_req;
				bool encoded = control_req.encode_e2ap_control_request(e2ap_buf, &e2ap_buf_size, ric_control_helper);
				if (encoded) {
					xapp_rmr_header header;
					header.state = RMR_OK;
					header.payload_length = e2ap_buf_size;
					header.message_type = RIC_CONTROL_REQ;

					strncpy((char *)header.meid, "gnb_001_001_0000019b", RMR_MAX_MEID);	// FIXME this should come from the RAN or cmd input args

					unsigned char *message = (unsigned char *)calloc(e2ap_buf_size, sizeof(unsigned char));
					memcpy(message, e2ap_buf, e2ap_buf_size);

					mdclog_write(MDCLOG_INFO, "Sending control request to %s", header.meid); // FIXME put the correct name

					bool sent = _ref_rmr->xapp_rmr_send(&header, (void *)message);
					free(message);
					if (!sent) {
						mdclog_write(MDCLOG_ERR, "Unable to send control request to %s", header.meid); // FIXME put the correct name
						return false;
					}

				} else {
					mdclog_write(MDCLOG_ERR, "E2AP Control Request encoding error. Reason = %s", control_req.get_error().c_str());
					return false;
				}
			}

			helper.status = "OK";

    } else {
      mdclog_write(MDCLOG_WARN, "A1 operation \"%s\" not implemented", helper.operation.c_str());
      return false;
    }

	  // Preparing response message to A1 Mediator
    if (! _ref_a1_handler->serialize_a1_response(message, message_len, helper)) {
			mdclog_write(MDCLOG_ERR, "Unable to serialize A1 reponse. Reason: %s", _ref_a1_handler->error_string.c_str());
			return false;
		}

  } else {
		mdclog_write(MDCLOG_ERR, "A1 policy type id %s not supported", helper.policy_type_id.c_str());
		return false;
	}

  return true;
}

//For processing received messages.XappMsgHandler should mention if resend is required or not.
void XappMsgHandler::operator()(rmr_mbuf_t *message, bool *resend)
{

	if (message->len > MAX_RMR_RECV_SIZE)
	{
		mdclog_write(MDCLOG_ERR, "Error : %s, %d, RMR message larger than %d. Ignoring ...", __FILE__, __LINE__, MAX_RMR_RECV_SIZE);
		return;
	}

	E2AP_PDU_t* e2pdu = (E2AP_PDU_t*)calloc(1, sizeof(E2AP_PDU));
	// int num = 0;

	switch (message->mtype)
	{
		// need to fix the health check.
		case (RIC_HEALTH_CHECK_REQ):
			message->mtype = RIC_HEALTH_CHECK_RESP; // if we're here we are running and all is ok
			message->sub_id = -1;
			strncpy((char *)message->payload, "Bouncer OK\n", rmr_payload_size(message));
			*resend = true;
			break;

		case (RIC_SUB_RESP):
			mdclog_write(MDCLOG_INFO, "Received subscription message of type = %d", message->mtype);
			unsigned char *me_id;
			if ((me_id = (unsigned char *)malloc(sizeof(unsigned char) * RMR_MAX_MEID)) == NULL)
			{
				mdclog_write(MDCLOG_ERR, "Error :  %s, %d : malloc failed for me_id", __FILE__, __LINE__);
				me_id = rmr_get_meid(message, NULL);
			}
			else
			{
				rmr_get_meid(message, me_id);
			}
			if (me_id == NULL)
			{
				mdclog_write(MDCLOG_ERR, " Error :: %s, %d : rmr_get_meid failed me_id is NULL", __FILE__, __LINE__);
				break;
			}
			mdclog_write(MDCLOG_INFO, "RMR Received MEID: %s", me_id);
			if (_ref_sub_handler != NULL)
			{
				_ref_sub_handler->manage_subscription_response(message->mtype, reinterpret_cast<char const *>(me_id));
			}
			else
			{
				mdclog_write(MDCLOG_ERR, " Error :: %s, %d : Subscription handler not assigned in message processor !", __FILE__, __LINE__);
			}
			*resend = false;
			if (me_id != NULL)
			{
				mdclog_write(MDCLOG_INFO, "Free RMR Received MEID memory: %s(0x%p)", me_id, me_id);
				free(me_id);
			}
			break;

		case (RIC_SUB_DEL_RESP):
			mdclog_write(MDCLOG_INFO, "Received subscription delete message of type = %d", message->mtype);
			// unsigned char *me_id;
			if ((me_id = (unsigned char *)malloc(sizeof(unsigned char) * RMR_MAX_MEID)) == NULL)
			{
				mdclog_write(MDCLOG_ERR, "Error :  %s, %d : malloc failed for me_id", __FILE__, __LINE__);
				me_id = rmr_get_meid(message, NULL);
			}
			else

			{
				rmr_get_meid(message, me_id);
			}
			if (me_id == NULL)
			{
				mdclog_write(MDCLOG_ERR, " Error :: %s, %d : rmr_get_meid failed me_id is NULL", __FILE__, __LINE__);
				break;
			}
			mdclog_write(MDCLOG_INFO, "RMR Received MEID: %s", me_id);
			if (_ref_sub_handler != NULL)
			{
				_ref_sub_handler->manage_subscription_response(message->mtype, reinterpret_cast<char const *>(me_id));
			}
			else
			{
				mdclog_write(MDCLOG_ERR, " Error :: %s, %d : Subscription handler not assigned in message processor !", __FILE__, __LINE__);
			}
			*resend = false;
			if (me_id != NULL)
			{
				mdclog_write(MDCLOG_INFO, "Free RMR Received MEID memory: %s(0x%p)", me_id, me_id);
				free(me_id);
			}
			break;

		case (RIC_INDICATION):
		{
			mdclog_write(MDCLOG_DEBUG, "Decoding indication for msg = %d, data_size = %d", message->mtype, message->len);

			ric_indication indication;
			ric_indication_helper ind_helper;
			// string error_msg;

			if (!indication.decode_e2ap_indication(message->payload, message->len, ind_helper)) {
				mdclog_write(MDCLOG_ERR, "Error decoding E2AP Indication. Reason: %s", indication.get_error().c_str());
				break;
			}

			// ######## this is specific for E2SM-KPM
			e2sm_indication kpm_indicaton;
			e2sm_kpm_indication_fmt1_helper kpm_helper;

			// FIXME not able to decode header correctly
			// if (!kpm_indicaton.decode_kpm_indication_header_format1(&ind_helper.indication_header, kpm_helper)) {
			// 	mdclog_write(MDCLOG_ERR, "Error decoding E2SM KPM Indication Header. Reason: %s", kpm_indicaton.get_error().c_str());
			// 	break;
			// }

			if (!kpm_indicaton.decode_kpm_indication_msg_format1(&ind_helper.indication_msg, kpm_helper)) {
				mdclog_write(MDCLOG_ERR, "Error decoding E2SM KPM Indication Message. Reason: %s", kpm_indicaton.get_error().c_str());
				break;
			}

			stringstream ss;
			// ss << "colletStartTime=" << kpm_helper.header.timestamp;
			for (auto it : kpm_helper.msg.measurements) {
				// ss << ", " << it.first << "=" << it.second;
				ss << it.first << "=" << it.second << " ";
			}

			mdclog_write(MDCLOG_INFO, "KPM Indication measurement values: %s", ss.str().c_str());
			// ######## end of specific for E2SM-KPM



			// TODO ######## this is specific for E2SM-RC with UE Admission Control
			// uint8_t ctrl_header_buf[8192] = {0, };
			// ssize_t ctrl_header_buf_size = 8192;

			// UEID_t *ueid = ind_helper.get_ui_id();

			// e2sm_control e2sm_control;
			// bool ret_head = e2sm_control.encode_rc_control_header(ctrl_header_buf, &ctrl_header_buf_size, ueid);
			// ASN_STRUCT_FREE(asn_DEF_UEID, ueid);	// we have to release here to avoid memory leaks if encoding returns false
			// if (!ret_head) {
			// 	mdclog_write(MDCLOG_ERR, "%s", e2sm_control.get_error().c_str());
			// 	*resend = false;
			// 	break;
			// }

			// uint8_t ctrl_msg_buf[8192] = {0, };
			// ssize_t ctrl_msg_buf_size = 8192;

			// e2sm_rc_control_helper control_msg_helper;
			// control_msg_helper.present = CONTROL_ACTION_PR_UE_ADMISSION_CONTROL;
			// bool ret_msg = e2sm_control.encode_rc_control_message(ctrl_msg_buf, &ctrl_msg_buf_size, &control_msg_helper);
			// if (!ret_msg) {
			// 	mdclog_write(MDCLOG_ERR, "%s", e2sm_control.get_error().c_str());
			// 	*resend = false;
			// 	break;
			// }

			// // E2AP Control Helper
			// ric_control_helper helper;
			// helper.requestor_id = ind_helper.request_id.ricRequestorID;
			// helper.instance_id = ind_helper.request_id.ricInstanceID;
			// helper.func_id = ind_helper.func_id;
			// // Control Call Process ID
			// helper.call_process_id = ind_helper.call_process_id.buf;
			// helper.call_process_id_size = ind_helper.call_process_id.size;
			// // Control ACK
			// helper.control_ack = RICcontrolAckRequest_noAck; // for now we do not require ACK messages for control requests
			// // Control Header
			// helper.control_header = ctrl_header_buf;
			// helper.control_header_size = ctrl_header_buf_size;
			// // Control Message
			// helper.control_msg = ctrl_msg_buf;
			// helper.control_msg_size = ctrl_msg_buf_size;

			// // E2AP buffer
			// uint8_t e2ap_buf[8192] = {0, };
			// ssize_t e2ap_buf_size = 8192;

			// ric_control_request control_req;
			// bool encoded = control_req.encode_e2ap_control_request(e2ap_buf, &e2ap_buf_size, helper);
			// if (encoded) {
			// 	message->mtype = RIC_CONTROL_REQ; // if we're here we are running and all is ok
			// 	message->sub_id = -1;

			// 	int rmr_len = rmr_payload_size(message);
			// 	if (rmr_len < 0) {
			// 		mdclog_write(MDCLOG_ERR, "unable to get the rmr payload size for control request. Reason = %s", strerror(errno));
			// 		*resend = false;
			// 		break;
			// 	}

			// 	if (e2ap_buf_size <= (ssize_t)rmr_len) {	// avoid compiler comparison complains
			// 		memcpy(message->payload, e2ap_buf, e2ap_buf_size);
			// 		message->len = e2ap_buf_size;
			// 		*resend = true;

			// 	} else {
			// 		mdclog_write(MDCLOG_ERR, "E2AP Control Request encoded size %lu exceeds rmr payload size %d", e2ap_buf_size, rmr_len);
			// 		*resend = false;
			// 	}
			// } else {
			// 	mdclog_write(MDCLOG_ERR, "E2AP Control Request encoding error. Reason = %s", control_req.get_error().c_str());
			// 	*resend = false;
			// }
			// TODO ######## end of specific for E2SM-RC with UE Admission Control


			if (mdclog_level_get() > MDCLOG_INFO)
				fprintf(stderr, "end of RIC_INDICATION case\n\n");
			// num++;
			// mdclog_write(MDCLOG_INFO, "Number of Indications Received = %d", num);
			break;
		}

		case A1_POLICY_REQ:
		{
			mdclog_write(MDCLOG_INFO, "In Message Handler: Received A1_POLICY_REQ.");

			a1_policy_helper helper;
			helper.handler_id = xapp_id;

			bool res=false;

			res = a1_policy_handler((char*)message->payload, &message->len, helper);
			if(res)
			{
				message->mtype = A1_POLICY_RESP;        // if we're here we are running and all is ok
				message->sub_id = -1;
				*resend = true;
			}
			break;

		}
		default:
			mdclog_write(MDCLOG_ERR, "Error :: Unknown message type %d received from RMR", message->mtype);
			*resend = false;
	}

	ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, e2pdu);
}


