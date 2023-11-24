use std::sync::Arc;
#[cfg(feature = "serialize_serde")]
use ::serde::{Deserialize, Serialize};
use atlas_common::error::*;
use atlas_common::globals::ReadOnly;
use atlas_common::ordering::{SeqNo};
use atlas_smr_application::app::UpdateBatch;
use atlas_smr_application::serialize::ApplicationData;
use atlas_smr_application::state::divisible_state::DivisibleState;
use atlas_smr_application::state::monolithic_state::MonolithicState;
use crate::ordering_protocol::{DecisionMetadata, View};
use crate::ordering_protocol::networking::serialize::{OrderingProtocolMessage, PermissionedOrderingProtocolMessage};
use crate::ordering_protocol::loggable::{PersistentOrderProtocolTypes, PProof};
use crate::smr::networking::serialize::DecisionLogMessage;
use crate::smr::smr_decision_log::{DecLog, DecLogMetadata, LoggingDecision, ShareableConsensusMessage};
use crate::state_transfer::{Checkpoint};


/// How should the data be written and response delivered?
/// If Sync is chosen the function will block on the call and return the result of the operation
/// If Async is chosen the function will not block and will return the response as a message to a channel
pub enum OperationMode {
    //When writing in async mode, you have the option of having the response delivered on a function
    //Of your choice
    //Note that this function will be executed on the persistent logging thread, so keep it short and
    //Be careful with race conditions.
    NonBlockingSync(Option<()>),
    BlockingSync,
}

pub trait PersistableStateTransferProtocol {}

/// The trait necessary for a persistent log protocol to be used as the persistent log layer
pub trait OrderingProtocolLog<D, OP>: Clone where OP: OrderingProtocolMessage<D> {
    /// Write to the persistent log the latest committed sequence number
    fn write_committed_seq_no(&self, write_mode: OperationMode, seq: SeqNo) -> Result<()>;

    /// Write a given message to the persistent log
    fn write_message(&self, write_mode: OperationMode, msg: ShareableConsensusMessage<D, OP>) -> Result<()>;

    /// Write the metadata for a given proof to the persistent log
    /// This in combination with the messages for that sequence number should form a valid proof
    fn write_decision_metadata(&self, write_mode: OperationMode, metadata: DecisionMetadata<D, OP>) -> Result<()>;

    /// Invalidate all messages with sequence number equal to the given one
    fn write_invalidate(&self, write_mode: OperationMode, seq: SeqNo) -> Result<()>;
}

/// The trait necessary for a permission logging protocol capable of simple
/// storage operations related to permissioned protocol messages
pub trait PermissionedOrderingProtocolLog<POP> where POP: PermissionedOrderingProtocolMessage {
    /// Write a view info into the persistent log
    fn write_view_info(&self, write_mode: OperationMode, view: View<POP>) -> Result<()>;

    /// Read a view info from the persistent log
    fn read_view_info(&self) -> Result<Option<View<POP>>>;
}

/// The trait that defines the the persistent decision log, so that the decision log can be persistent
pub trait PersistentDecisionLog<D, OPM, POP, LS>: OrderingProtocolLog<D, OPM> + Send
    where D: ApplicationData,
          OPM: OrderingProtocolMessage<D>,
          POP: PersistentOrderProtocolTypes<D, OPM>,
          LS: DecisionLogMessage<D, OPM, POP> {
    /// A checkpoint has been done on the state, so we can clear the current decision log
    fn checkpoint_received(&self, mode: OperationMode, seq: SeqNo) -> Result<()>;

    /// Write a given proof to the persistent log
    fn write_proof(&self, write_mode: OperationMode, proof: PProof<D, OPM, POP>) -> Result<()>;

    /// Write the metadata of a decision into the persistent log
    fn write_decision_log_metadata(&self, mode: OperationMode, log_metadata: DecLogMetadata<D, OPM, POP, LS>) -> Result<()>;

    /// Write the decision log into the persistent log
    fn write_decision_log(&self, mode: OperationMode, log: DecLog<D, OPM, POP, LS>) -> Result<()>;

    /// Read a proof from the log with the given sequence number
    fn read_proof(&self, mode: OperationMode, seq: SeqNo) -> Result<Option<PProof<D, OPM, POP>>>;

    /// Read the decision log from the persistent storage
    fn read_decision_log(&self, mode: OperationMode) -> Result<Option<DecLog<D, OPM, POP, LS>>>;

    /// Reset the decision log on disk
    fn reset_log(&self, mode: OperationMode) -> Result<()>;

    /// Wait for the persistence of a given proof, if necessary
    /// The return of this function is dependent on the current mode of the persistent log.
    /// Namely, if we have to perform some sort of operations before the decision can be safely passed
    /// to the executor, then we want to return [None] on this function. If there is no need
    /// of further persistence, then the decision should be re returned with
    /// [Some(ProtocolConsensusDecision<D::Request>)]
    fn wait_for_full_persistence(&self, batch: UpdateBatch<D::Request>, decision_logging: LoggingDecision)
                                 -> Result<Option<UpdateBatch<D::Request>>>;
}

///
/// The trait necessary for a logging protocol capable of handling monolithic states.
///
pub trait MonolithicStateLog<S>: Send where S: MonolithicState {
    /// Read the local checkpoint from the persistent log
    fn read_checkpoint(&self) -> Result<Option<Checkpoint<S>>>;

    /// Write a checkpoint to the persistent log
    fn write_checkpoint(
        &self,
        write_mode: OperationMode,
        checkpoint: Arc<ReadOnly<Checkpoint<S>>>,
    ) -> Result<()>;
}

///
/// The trait necessary for a logging protocol capable of handling divisible states.
///
pub trait DivisibleStateLog<S>: Send where S: DivisibleState {
    /// Read the descriptor of the local state
    fn read_local_descriptor(&self) -> Result<Option<S::StateDescriptor>>;

    /// Read a part from the local state log
    fn read_local_part(&self, part: S::PartDescription) -> Result<Option<S::StatePart>>;

    /// Write the descriptor of a state
    fn write_descriptor(&self, write_mode: OperationMode,
                        checkpoint: S::StateDescriptor, ) -> Result<()>;

    /// Write a given set of parts to the log
    fn write_parts(&self, write_mode: OperationMode,
                   parts: Vec<Arc<ReadOnly<S::StatePart>>>, ) -> Result<()>;

    /// Write a given set of parts and the descriptor of the state
    fn write_parts_and_descriptor(&self, write_mode: OperationMode, descriptor: S::StateDescriptor,
                                  parts: Vec<Arc<ReadOnly<S::StatePart>>>) -> Result<()>;

    /// Delete a given part from the log
    fn delete_part(&self, write_mode: OperationMode, part: S::PartDescription) -> Result<()>;
}