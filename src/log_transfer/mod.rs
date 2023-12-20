use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use atlas_common::error::*;
use atlas_common::maybe_vec::MaybeVec;
use atlas_common::ordering::SeqNo;
use atlas_communication::message::StoredMessage;
use atlas_communication::protocol_node::ProtocolNetworkNode;
use atlas_communication::reconfiguration_node::NetworkInformationProvider;
use atlas_smr_application::serialize::ApplicationData;

use crate::log_transfer::networking::serialize::LogTransferMessage;
use crate::ordering_protocol::loggable::{LoggableOrderProtocol, PersistentOrderProtocolTypes};
use crate::ordering_protocol::networking::serialize::{NetworkView, OrderingProtocolMessage};
use crate::ordering_protocol::{OrderingProtocol, PermissionedOrderingProtocol};
use crate::persistent_log::{PersistentDecisionLog};
use crate::smr::smr_decision_log::{DecisionLog, PartiallyWriteableDecLog, LoggedDecision, ShareableMessage};
use crate::timeouts::{RqTimeout, Timeouts};

pub mod networking;

pub type LogTM<D, OP, M: LogTransferMessage<D, OP>> = <M as LogTransferMessage<D, OP>>::LogTransferMessage;

/// The result of processing a message in the log transfer protocol
pub enum LTResult<D: ApplicationData> {
    RunLTP,
    NotNeeded,
    Running,
    Ignored,
    /// The log transfer protocol has reached a point where we can already say which is
    /// the current seq number of the quorum
    InstallSeq(SeqNo),
    /// The log transfer protocol has finished and the ordering protocol should now
    /// be proceeded. The requests contained are requests that must be executed by the application
    /// in order to reach the state that corresponds to the decision log
    /// FirstSeq and LastSeq of the installed log downloaded from other replicas and the requests that should be executed
    LTPFinished(SeqNo, SeqNo, MaybeVec<LoggedDecision<D::Request>>),
}

/// Log Transfer protocol timeout result
pub enum LTTimeoutResult {
    RunLTP,
    NotNeeded,
}

/// Log Transfer polling result
pub enum LTPollResult<LT, D: ApplicationData> {
    ReceiveMsg,
    RePoll,
    Exec(StoredMessage<LT>),
    LTResult(LTResult<D>),
}

/// Log transfer protocol.
/// This protocol is meant to work in tandem with the [DecisionLog] abstraction, meaning
/// it has to actually "hook" into it and directly use functions from the DecisionLog.
/// Examples are, for example using the [DecisionLog::snapshot_log] when wanting a snapshot
/// of the current log, [DecisionLog::install_log] when we want to install a log that
/// we have received.
/// This level of coupling exists because we need to be able to reference the decision log
/// in order to obtain the current log (cloning it and passing it to this function every time
/// would be extremely expensive) and since this protocol only makes sense when paired with
/// the [DecisionLog], we decided that it makes sense for them to be more tightly coupled.
///TODO: Work on Getting partial log installations integrated with this log transfer
/// trait via [PartiallyWriteableDecLog]
pub trait LogTransferProtocol<D, OP, DL, NT, PL> : Send where D: ApplicationData + 'static,
                                                       OP: LoggableOrderProtocol<D, NT>,
                                                       DL: DecisionLog<D, OP, NT, PL> {
    /// The type which implements StateTransferMessage, to be implemented by the developer
    type Serialization: LogTransferMessage<D, OP::Serialization> + 'static;

    /// The configuration type the protocol wants to accept
    type Config: Send + 'static;

    /// Initialize the log transferring protocol
    fn initialize(config: Self::Config, timeout: Timeouts, node: Arc<NT>, log: PL) -> Result<Self>
        where Self: Sized;

    /// Request the latest logs from the rest of the replicas
    fn request_latest_log<V>(&mut self, decision_log: &mut DL, view: V) -> Result<()>
        where PL: PersistentDecisionLog<D, OP::Serialization, OP::PersistableTypes, DL::LogSerialization>,
              V: NetworkView;

    /// Polling method for the log transfer protocol
    fn poll(&mut self) -> Result<LTPollResult<LogTM<D, OP::Serialization, Self::Serialization>, D>>;

    /// Handle a state transfer protocol message that was received while executing the ordering protocol
    fn handle_off_ctx_message<V>(&mut self, decision_log: &mut DL,
                                 view: V,
                                 message: StoredMessage<LogTM<D, OP::Serialization, Self::Serialization>>)
                                 -> Result<()>
        where PL: PersistentDecisionLog<D, OP::Serialization, OP::PersistableTypes, DL::LogSerialization>,
              V: NetworkView;

    /// Process a log transfer protocol message, received from other replicas
    fn process_message<V>(&mut self, decision_log: &mut DL, view: V,
                          message: StoredMessage<LogTM<D, OP::Serialization, Self::Serialization>>) -> Result<LTResult<D>>
        where PL: PersistentDecisionLog<D, OP::Serialization, OP::PersistableTypes, DL::LogSerialization>,
              V: NetworkView;

    /// Handle a timeout received from the timeout layer
    fn handle_timeout<V>(&mut self, view: V, timeout: Vec<RqTimeout>) -> Result<LTTimeoutResult>
        where PL: PersistentDecisionLog<D, OP::Serialization, OP::PersistableTypes, DL::LogSerialization>,
              V: NetworkView;
}

impl<D: ApplicationData> Debug for LTResult<D> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LTResult::RunLTP => {
                write!(f, "RunLTP")
            }
            LTResult::NotNeeded => {
                write!(f, "NotNeeded")
            }
            LTResult::Running => {
                write!(f, "Running")
            }
            LTResult::LTPFinished(first, last, _) => {
                write!(f, "LTPFinished({:?}, {:?})", first, last)
            }
            LTResult::InstallSeq(seq) => {
                write!(f, "LTPInstallSeq({:?})", seq)
            }
            LTResult::Ignored => {
                write!(f, "Ignored Message")
            }
        }
    }
}