use std::sync::Arc;
#[cfg(feature = "serialize_serde")]
use ::serde::{Deserialize, Serialize};
use atlas_common::error::*;
use atlas_common::globals::ReadOnly;
use atlas_common::ordering::{SeqNo};
use atlas_communication::message::StoredMessage;
use atlas_smr_application::serialize::ApplicationData;
use atlas_smr_application::state::divisible_state::DivisibleState;
use atlas_smr_application::state::monolithic_state::MonolithicState;
use crate::ordering_protocol::stateful_order_protocol::DecLog;
use crate::ordering_protocol::{DecisionMetadata, LoggableMessage, SerProof, SerProofMetadata, View};
use crate::ordering_protocol::networking::serialize::{OrderingProtocolMessage, PermissionedOrderingProtocolMessage, StatefulOrderProtocolMessage};
use crate::ordering_protocol::loggable::PersistentOrderProtocolTypes;
use crate::smr::networking::serialize::DecisionLogMessage;
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

/// Shortcuts for the types used in the protocol
/// The trait with all the necessary types for the protocol to be used with our persistent storage system
/// We need this because of the way the messages are stored. Since we want to store the messages at the same
/// time we are receiving them, we divide the messages into various instances of KV-DB (which also parallelizes the
/// writing into them).
pub trait PersistableOrderProtocol<D, OPM, SOPM> where OPM: OrderingProtocolMessage<D>, SOPM: StatefulOrderProtocolMessage<D, OPM> {
    /// The types of messages to be stored. This is used due to the parallelization described above.
    /// Each of the names provided here will be a different KV-DB instance (in the case of RocksDB, a column family)
    fn message_types() -> Vec<&'static str>;

    /// Get the message type for a given message, must correspond to a string returned by
    /// [PersistableOrderProtocol::message_types]
    fn get_type_for_message(msg: &LoggableMessage<D, OPM>) -> Result<&'static str>;

    /// Initialize a proof from the metadata and messages stored in persistent storage
    fn init_proof_from(metadata: SerProofMetadata<D, OPM>, messages: Vec<StoredMessage<LoggableMessage<D, OPM>>>) -> SerProof<D, OPM>;

    /// Initialize a decision log from the messages stored in persistent storage
    fn init_dec_log(proofs: Vec<SerProof<D, OPM>>) -> DecLog<D, OPM, SOPM>;

    /// Decompose a given proof into it's metadata and messages, ready to be persisted
    fn decompose_proof(proof: &SerProof<D, OPM>) -> (&SerProofMetadata<D, OPM>, Vec<&StoredMessage<LoggableMessage<D, OPM>>>);

    /// Decompose a decision log into its separate proofs, so they can then be further decomposed
    /// into metadata and messages
    fn decompose_dec_log(proofs: &DecLog<D, OPM, SOPM>) -> Vec<&SerProof<D, OPM>>;
}

pub trait PersistableStateTransferProtocol {}

/// The trait necessary for a persistent log protocol to be used as the persistent log layer
pub trait OrderingProtocolLog<D, OP>: Clone where OP: OrderingProtocolMessage<D> {
    /// Write to the persistent log the latest committed sequence number
    fn write_committed_seq_no(&self, write_mode: OperationMode, seq: SeqNo) -> Result<()>;

    /// Write a given message to the persistent log
    fn write_message(&self, write_mode: OperationMode, msg: Arc<ReadOnly<StoredMessage<LoggableMessage<D, OP>>>>) -> Result<()>;

    /// Write the metadata for a given proof to the persistent log
    /// This in combination with the messages for that sequence number should form a valid proof
    fn write_proof_metadata(&self, write_mode: OperationMode, metadata: SerProofMetadata<D, OP>) -> Result<()>;

    /// Write a given proof to the persistent log
    fn write_proof(&self, write_mode: OperationMode, proof: SerProof<D, OP>) -> Result<()>;

    /// Invalidate all messages with sequence number equal to the given one
    fn write_invalidate(&self, write_mode: OperationMode, seq: SeqNo) -> Result<()>;

    /// Read a proof from the log with the given sequence number
    fn read_proof(&self, seq: SeqNo) -> Result<Option<SerProof<D, OP>>>;
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
pub trait PersistentDecisionLog<D, OPM, POP, DOP>: OrderingProtocolLog<D, OPM>
    where D: ApplicationData,
          OPM: OrderingProtocolMessage<D>,
          POP: PersistentOrderProtocolTypes<D, OPM>,
          DOP: DecisionLogMessage<D, OPM, POP> {

    /// A checkpoint has been done on the state, so we can clear the current decision log
    fn checkpoint_received<OPL>(&self, mode: OperationMode, seq: SeqNo);

    /// Finalize the writing of a given proof
    fn finalize_proof_write<OPL>(&self, mode: OperationMode, seq: SeqNo, metadata: DecisionMetadata<D, OPM>);

    /// Read the decision log from the persistent storage
    fn read_decision_log<OPL>(&self, mode: OperationMode) -> Result<Option<DecLog<D, OPM, DOP>>>;

    /// Write the decision log into the persistent log
    fn write_decision_log<OPL>(&self, mode: OperationMode, log: DecLog<D, OPM, DOP>) -> Result<()>;
}

/// Complements the default [`OrderingProtocolLog`] with methods for proofs and decided logs
pub trait StatefulOrderingProtocolLog<D, OPM, SOPM, POP>: OrderingProtocolLog<D, OPM>
    where OPM: OrderingProtocolMessage<D>, SOPM: StatefulOrderProtocolMessage<D, OPM>, POP: PermissionedOrderingProtocolMessage {
    /// Write to the persistent log the latest View information
    fn write_view_info(&self, write_mode: OperationMode, view_seq: View<POP>) -> Result<()>;

    /// Read the state from the persistent log
    fn read_state(&self, write_mode: OperationMode) -> Result<Option<(View<POP>, DecLog<D, OPM, SOPM>)>>;

    /// Write a given decision log to the persistent log
    fn write_install_state(&self, write_mode: OperationMode, view: View<POP>, dec_log: DecLog<D, OPM, SOPM>) -> Result<()>;
}

///
/// The trait necessary for a logging protocol capable of handling monolithic states.
///
pub trait MonolithicStateLog<S> where S: MonolithicState {
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
pub trait DivisibleStateLog<S> where S: DivisibleState {
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