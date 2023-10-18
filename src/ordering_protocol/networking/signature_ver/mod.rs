use std::sync::Arc;

use atlas_common::error::*;
use atlas_communication::message::Header;
use atlas_communication::message_signing::NetworkMessageSignatureVerifier;
use atlas_communication::reconfiguration_node::NetworkInformationProvider;
use atlas_smr_application::serialize::ApplicationData;

use crate::log_transfer::networking::serialize::LogTransferMessage;
use crate::messages::{ReplyMessage, RequestMessage, SystemMessage};
use crate::messages::signature_ver::SigVerifier;
use crate::ordering_protocol::networking::serialize::OrderingProtocolMessage;
use crate::serialize::Service;
use crate::state_transfer::networking::serialize::StateTransferMessage;

/// This is a helper trait to verify signatures of messages for the ordering protocol
pub trait OrderProtocolSignatureVerificationHelper<D, OP, NI> where D: ApplicationData, OP: OrderingProtocolMessage<D>, NI: NetworkInformationProvider {
    /// This is a helper to verify internal player requests
    fn verify_request_message(network_info: &Arc<NI>, header: &Header, request: RequestMessage<D::Request>) -> Result<RequestMessage<D::Request>>;

    /// Another helper to verify internal player replies
    fn verify_reply_message(network_info: &Arc<NI>, header: &Header, reply: ReplyMessage<D::Reply>) -> Result<ReplyMessage<D::Reply>>;

    /// helper mostly to verify forwarded consensus messages, for example
    fn verify_protocol_message(network_info: &Arc<NI>, header: &Header, message: OP::ProtocolMessage) -> Result<OP::ProtocolMessage>;
}

impl<SV, NI, D, P, S, L> OrderProtocolSignatureVerificationHelper<D, P, NI> for SigVerifier<SV, NI, D, P, S, L>
    where D: ApplicationData + 'static,
          P: OrderingProtocolMessage<D> + 'static,
          L: LogTransferMessage<D, P> + 'static,
          S: StateTransferMessage + 'static,
          NI: NetworkInformationProvider + 'static,
          SV: NetworkMessageSignatureVerifier<Service<D, P, S, L>, NI>
{
    fn verify_request_message(network_info: &Arc<NI>, header: &Header, request: RequestMessage<D::Request>) -> Result<RequestMessage<D::Request>> {
        let message = SystemMessage::<D, P::ProtocolMessage, S::StateTransferMessage, L::LogTransferMessage>::OrderedRequest(request);

        let message = SV::verify_signature(network_info, header, message)?;

        if let SystemMessage::OrderedRequest(r) = message {
            Ok(r)
        } else {
            unreachable!()
        }
    }

    fn verify_reply_message(network_info: &Arc<NI>, header: &Header, reply: ReplyMessage<D::Reply>) -> Result<ReplyMessage<D::Reply>> {
        let message = SystemMessage::<D, P::ProtocolMessage, S::StateTransferMessage, L::LogTransferMessage>::OrderedReply(reply);

        let message = SV::verify_signature(network_info, header, message)?;

        if let SystemMessage::OrderedReply(r) = message {
            Ok(r)
        } else {
            unreachable!()
        }
    }

    fn verify_protocol_message(network_info: &Arc<NI>, header: &Header, message: P::ProtocolMessage) -> Result<P::ProtocolMessage> {
        let message = SystemMessage::<D, P::ProtocolMessage, S::StateTransferMessage, L::LogTransferMessage>::from_protocol_message(message);

        let message = SV::verify_signature(network_info, header, message)?;

        if let SystemMessage::ProtocolMessage(r) = message {
            Ok(r.into_inner())
        } else {
            unreachable!()
        }
    }
}