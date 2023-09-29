use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use atlas_common::crypto::hash::Digest;
use atlas_common::error::*;
use atlas_common::node_id::NodeId;
use atlas_common::ordering::{Orderable, SeqNo};
use atlas_communication::message::StoredMessage;
use atlas_smr_application::app::UpdateBatch;
use atlas_smr_application::ExecutorHandle;
use atlas_smr_application::serialize::ApplicationData;

use crate::messages::{ClientRqInfo, Protocol};
use crate::ordering_protocol::networking::serialize::{OrderingProtocolMessage, PermissionedOrderingProtocolMessage};
use crate::persistent_log::OrderingProtocolLog;
use crate::request_pre_processing::{BatchOutput, RequestPreProcessor};
use crate::timeouts::{RqTimeout, Timeouts};

pub mod reconfigurable_order_protocol;
pub mod stateful_order_protocol;
pub mod networking;
pub mod persistable;

pub type View<POP: PermissionedOrderingProtocolMessage> = <POP as PermissionedOrderingProtocolMessage>::ViewInfo;

pub type ProtocolMessage<D, OP> = <OP as OrderingProtocolMessage<D>>::ProtocolMessage;
pub type LoggableMessage<D, OP> = <OP as OrderingProtocolMessage<D>>::LoggableMessage;
pub type SerProof<D, OP> = <OP as OrderingProtocolMessage<D>>::Proof;
pub type SerProofMetadata<D, OP> = <OP as OrderingProtocolMessage<D>>::ProofMetadata;

pub struct OrderingProtocolArgs<D, NT, PL>(pub ExecutorHandle<D>, pub Timeouts,
                                           pub RequestPreProcessor<D::Request>,
                                           pub BatchOutput<D::Request>, pub Arc<NT>,
                                           pub PL, pub Vec<NodeId>) where D: ApplicationData;

pub trait OrderProtocolTolerance {
    fn get_n_for_f(f: usize) -> usize;
}

/// The trait for an ordering protocol to be implemented in Atlas
pub trait OrderingProtocol<D, NT, PL>: OrderProtocolTolerance + Orderable where D: ApplicationData + 'static {
    /// The type which implements OrderingProtocolMessage, to be implemented by the developer
    type Serialization: OrderingProtocolMessage<D> + 'static;

    /// The configuration type the protocol wants to accept
    type Config;

    /// Initialize this ordering protocol with the given configuration, executor, timeouts and node
    fn initialize(config: Self::Config, args: OrderingProtocolArgs<D, NT, PL>) -> Result<Self> where
        Self: Sized;

    /// Handle a protocol message that was received while we are executing another protocol
    fn handle_off_ctx_message(&mut self, message: StoredMessage<Protocol<ProtocolMessage<D, Self::Serialization>>>)
        where PL: OrderingProtocolLog<D, Self::Serialization>;

    /// Handle the protocol being executed having changed (for example to the state transfer protocol)
    /// This is important for some of the protocols, which need to know when they are being executed or not
    fn handle_execution_changed(&mut self, is_executing: bool) -> Result<()>;

    /// Poll from the ordering protocol in order to know what we should do next
    /// We do this to check if there are already messages waiting to be executed that were received ahead of time and stored.
    /// Or whether we should run state transfer or wait for messages from other replicas
    fn poll(&mut self) -> OrderProtocolPoll<ProtocolMessage<D, Self::Serialization>, D::Request>
        where PL: OrderingProtocolLog<D, Self::Serialization>;

    /// Process a protocol message that we have received
    /// This can be a message received from the poll() method or a message received from other replicas.
    fn process_message(&mut self, message: StoredMessage<Protocol<ProtocolMessage<D, Self::Serialization>>>) -> Result<OrderProtocolExecResult<D::Request>>
        where PL: OrderingProtocolLog<D, Self::Serialization>;

    /// Get the current sequence number of the protocol, combined with a proof of it so we can send it to other replicas
    fn sequence_number_with_proof(&self) -> Result<Option<(SeqNo, SerProof<D, Self::Serialization>)>>
        where PL: OrderingProtocolLog<D, Self::Serialization>;

    /// Verify the sequence number sent by another replica. This doesn't pass a mutable reference since we don't want to
    /// make any changes to the state of the protocol here (or allow the implementer to do so). Instead, we want to
    /// just verify this sequence number
    fn verify_sequence_number(&self, seq_no: SeqNo, proof: &SerProof<D, Self::Serialization>) -> Result<bool>;

    /// Install a given sequence number
    fn install_seq_no(&mut self, seq_no: SeqNo) -> Result<()>
        where PL: OrderingProtocolLog<D, Self::Serialization>;

    /// Handle a timeout received from the timeouts layer
    fn handle_timeout(&mut self, timeout: Vec<RqTimeout>) -> Result<OrderProtocolExecResult<D::Request>>
        where PL: OrderingProtocolLog<D, Self::Serialization>;
}


/// A permissioned ordering protocol, meaning only a select few are actually part of the quorum that decides the
/// ordering of the operations.
pub trait PermissionedOrderingProtocol {

    type PermissionedSerialization: PermissionedOrderingProtocolMessage + 'static;

    /// Get the current view of the ordering protocol
    fn view(&self) -> View<Self::PermissionedSerialization>;

    /// Install a given view into the ordering protocol
    fn install_view(&mut self, view: View<Self::PermissionedSerialization>);
}

/// result from polling the ordering protocol
pub enum OrderProtocolPoll<P, O> {
    RunCst,
    ReceiveFromReplicas,
    Exec(StoredMessage<Protocol<P>>),
    Decided(Vec<ProtocolConsensusDecision<O>>),
    QuorumJoined(Option<Vec<ProtocolConsensusDecision<O>>>, NodeId, Vec<NodeId>),
    RePoll,
}

/// Result from executing a message in the ordering protocol
pub enum OrderProtocolExecResult<O> {
    Success,
    Decided(Vec<ProtocolConsensusDecision<O>>),
    RunCst,
    QuorumJoined(Option<Vec<ProtocolConsensusDecision<O>>>, NodeId, Vec<NodeId>),
}

/// Information reported after a logging operation.
pub enum ExecutionResult {
    /// Nothing to report.
    Nil,
    /// The log became full. We are waiting for the execution layer
    /// to provide the current serialized application state, so we can
    /// complete the log's garbage collection and eventually its
    /// checkpoint.
    BeginCheckpoint,
}

/// The struct representing a consensus decision
///
/// Executable Batch: All of the requests that should be executed, in the correct order
/// Execution Result: Whether we need to ask the executor for a checkpoint in order to reset the current message log
/// Batch info: The information collected by the [DecidingLog], if applicable. (We can receive a batch
/// via a complete proof which means this will be [None] or we can process a batch normally, which means
/// this will be [Some(CompletedBatch<D>)])
pub struct ProtocolConsensusDecision<O> {
    /// The sequence number of the batch
    seq: SeqNo,

    /// The consensus decision
    executable_batch: UpdateBatch<O>,

    /// Additional information about a batch
    batch_info: Option<DecisionInformation>,
}

/// Information about the completed batch,
/// when the batch was completed locally
#[derive(Debug)]
pub struct DecisionInformation {
    // The digest of the batch
    batch_digest: Digest,
    // The messages that must be persisted in order for this batch to be considered
    // persisted and ready to be executed
    messages_persisted: Vec<Digest>,
    // The information about all contained requests
    client_requests: Vec<ClientRqInfo>,
}

impl<P, O> Debug for OrderProtocolPoll<P, O> where P: Debug {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OrderProtocolPoll::RunCst => {
                write!(f, "RunCst")
            }
            OrderProtocolPoll::ReceiveFromReplicas => {
                write!(f, "Receive From Replicas")
            }
            OrderProtocolPoll::Exec(message) => {
                write!(f, "Exec message {:?}", message.message())
            }
            OrderProtocolPoll::RePoll => {
                write!(f, "RePoll")
            }
            OrderProtocolPoll::Decided(rqs) => {
                write!(f, "{} committed decisions", rqs.len())
            }
            OrderProtocolPoll::QuorumJoined(decs, node, quorum) => {
                write!(f, "{:?} Joined Quorum. Current: {:?}. {} decisions", node, quorum, decs.as_ref().map(|d| d.len()).unwrap_or(0))
            }
        }
    }
}

/// Constructor for the ProtocolConsensusDecision struct
impl<O> ProtocolConsensusDecision<O> {
    pub fn new(seq: SeqNo,
               executable_batch: UpdateBatch<O>,
               batch_info: Option<DecisionInformation>) -> Self {
        ProtocolConsensusDecision {
            seq,
            executable_batch,
            batch_info,
        }
    }

    pub fn batch_info(&self) -> &Option<DecisionInformation> {
        &self.batch_info
    }

    pub fn into(self) -> (SeqNo, UpdateBatch<O>, Option<DecisionInformation>) {
        (self.seq, self.executable_batch, self.batch_info)
    }

    pub fn update_batch(&self) -> &UpdateBatch<O> {
        &self.executable_batch
    }
}

/// Constructor for the DecisionInformation struct
impl DecisionInformation {
    pub fn new(batch_digest: Digest, messages_persisted: Vec<Digest>, client_requests: Vec<ClientRqInfo>) -> Self {
        DecisionInformation {
            batch_digest,
            messages_persisted,
            client_requests,
        }
    }

    pub fn batch_digest(&self) -> &Digest {
        &self.batch_digest
    }

    pub fn messages_persisted(&self) -> &Vec<Digest> {
        &self.messages_persisted
    }

    pub fn client_requests(&self) -> &Vec<ClientRqInfo> {
        &self.client_requests
    }
}

impl<O> Debug for ProtocolConsensusDecision<O> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProtocolConsensusDecision {{ seq: {:?}, executable_batch: {:?}, batch_info: {:?} }}", self.seq, self.executable_batch.len(), self.batch_info)
    }
}