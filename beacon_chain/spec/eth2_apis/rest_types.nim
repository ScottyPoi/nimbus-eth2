# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Types used by both client and server in the common REST API:
# https://ethereum.github.io/eth2.0-APIs/#/
# Be mindful that changing these changes the serialization and deserialization
# in the API which may lead to incompatibilities between clients - tread
# carefully!

{.push raises: [Defect].}

import
  std/[json, typetraits],
  stew/base10,
  ".."/forks,
  ".."/datatypes/[phase0, altair]

export forks, phase0, altair

const
  # https://github.com/ethereum/eth2.0-APIs/blob/master/apis/beacon/states/validator_balances.yaml#L17
  # https://github.com/ethereum/eth2.0-APIs/blob/master/apis/beacon/states/validators.yaml#L17
  MaximumValidatorIds* = 16384

type
  EventTopic* {.pure.} = enum
    Head, Block, Attestation, VoluntaryExit, FinalizedCheckpoint, ChainReorg,
    ContributionAndProof

  EventTopics* = set[EventTopic]

  RestValidatorIndex* = distinct uint64

  ValidatorQueryKind* {.pure.} = enum
    Index, Key

  ValidatorIdent* = object
    case kind*: ValidatorQueryKind
    of ValidatorQueryKind.Index:
      index*: RestValidatorIndex
    of ValidatorQueryKind.Key:
      key*: ValidatorPubKey

  ValidatorFilterKind* {.pure.} = enum
    PendingInitialized, PendingQueued,
    ActiveOngoing, ActiveExiting, ActiveSlashed,
    ExitedUnslashed, ExitedSlashed,
    WithdrawalPossible, WithdrawalDone

  ValidatorFilter* = set[ValidatorFilterKind]

  StateQueryKind* {.pure.} = enum
    Slot, Root, Named

  StateIdentType* {.pure.} = enum
    Head, Genesis, Finalized, Justified

  StateIdent* = object
    case kind*: StateQueryKind
    of StateQueryKind.Slot:
      slot*: Slot
    of StateQueryKind.Root:
      root*: Eth2Digest
    of StateQueryKind.Named:
      value*: StateIdentType

  BlockQueryKind* {.pure.} = enum
    Slot, Root, Named
  BlockIdentType* {.pure.} = enum
    Head, Genesis, Finalized

  BlockIdent* = object
    case kind*: BlockQueryKind
    of BlockQueryKind.Slot:
      slot*: Slot
    of BlockQueryKind.Root:
      root*: Eth2Digest
    of BlockQueryKind.Named:
      value*: BlockIdentType

  PeerStateKind* {.pure.} = enum
    Disconnected, Connecting, Connected, Disconnecting

  PeerDirectKind* {.pure.} = enum
    Inbound, Outbound

  RestAttesterDuty* = object
    pubkey*: ValidatorPubKey
    validator_index*: ValidatorIndex
    committee_index*: CommitteeIndex
    committee_length*: uint64
    committees_at_slot*: uint64
    validator_committee_index*: ValidatorIndex
    slot*: Slot

  RestProposerDuty* = object
    pubkey*: ValidatorPubKey
    validator_index*: ValidatorIndex
    slot*: Slot

  RestSyncCommitteeDuty* = object
    pubkey*: ValidatorPubKey
    validator_index*: ValidatorIndex
    validator_sync_committee_indices*: seq[SyncSubcommitteeIndex]

  RestSyncCommitteeMessage* = object
    slot*: Slot
    beacon_block_root*: Eth2Digest
    validator_index*: uint64
    signature*: ValidatorSig

  RestSyncCommitteeContribution* = object
    slot*: Slot
    beacon_block_root*: Eth2Digest
    subcommittee_index*: uint64
    aggregation_bits*: SyncCommitteeAggregationBits ##\
    signature*: ValidatorSig

  RestContributionAndProof* = object
    aggregator_index*: uint64
    selection_proof*: ValidatorSig
    contribution*: RestSyncCommitteeContribution

  RestSignedContributionAndProof* = object
    message*: RestContributionAndProof
    signature*: ValidatorSig

  RestCommitteeSubscription* = object
    validator_index*: ValidatorIndex
    committee_index*: CommitteeIndex
    committees_at_slot*: uint64
    slot*: Slot
    is_aggregator*: bool

  RestSyncCommitteeSubscription* = object
    validator_index*: ValidatorIndex
    sync_committee_indices*: seq[SyncSubcommitteeIndex]
    until_epoch*: Epoch

  RestBeaconStatesFinalityCheckpoints* = object
    previous_justified*: Checkpoint
    current_justified*: Checkpoint
    finalized*: Checkpoint

  RestGenesis* = object
    genesis_time*: uint64
    genesis_validators_root*: Eth2Digest
    genesis_fork_version*: Version

  RestValidatorBalance* = object
    index*: ValidatorIndex
    balance*: string

  RestBeaconStatesCommittees* = object
    index*: CommitteeIndex
    slot*: Slot
    validators*: seq[ValidatorIndex]

  RestFailureItem* = object
    index*: uint64
    message*: string

  RestAttestationsFailure* = object
    index*: uint64
    message*: string

  RestValidator* = object
    index*: ValidatorIndex
    balance*: string
    status*: string
    validator*: Validator

  RestBlockHeader* = object
    slot*: Slot
    proposer_index*: ValidatorIndex
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body_root*: Eth2Digest

  RestSignedBlockHeader* = object
    message*: RestBlockHeader
    signature*: ValidatorSig

  RestBlockHeaderInfo* = object
    root*: Eth2Digest
    canonical*: bool
    header*: RestSignedBlockHeader

  RestNodePeer* = object
    peer_id*: string
    enr*: string
    last_seen_p2p_address*: string
    state*: string
    direction*: string
    agent*: string # This is not part of specification
    proto*: string # This is not part of specification

  RestNodeVersion* = object
    version*: string

  RestSyncInfo* = object
    head_slot*: Slot
    sync_distance*: uint64
    is_syncing*: bool

  RestPeerCount* = object
    disconnected*: uint64
    connecting*: uint64
    connected*: uint64
    disconnecting*: uint64

  RestChainHead* = object
    root*: Eth2Digest
    slot*: Slot

  RestMetadata* = object
    seq_number*: string
    attnets*: string

  RestNetworkIdentity* = object
   peer_id*: string
   enr*: string
   p2p_addresses*: seq[string]
   discovery_addresses*: seq[string]
   metadata*: RestMetadata

  RestSpec* = object
    CONFIG_NAME*: string
    PRESET_BASE*: string
    ALTAIR_FORK_EPOCH*: Epoch
    ALTAIR_FORK_VERSION*: Version
    MAX_COMMITTEES_PER_SLOT*: uint64
    TARGET_COMMITTEE_SIZE*: uint64
    MAX_VALIDATORS_PER_COMMITTEE*: uint64
    MIN_PER_EPOCH_CHURN_LIMIT*: uint64
    CHURN_LIMIT_QUOTIENT*: uint64
    SHUFFLE_ROUND_COUNT*: uint64
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT*: uint64
    MIN_GENESIS_TIME*: uint64
    HYSTERESIS_QUOTIENT*: uint64
    HYSTERESIS_DOWNWARD_MULTIPLIER*: uint64
    HYSTERESIS_UPWARD_MULTIPLIER*: uint64
    SAFE_SLOTS_TO_UPDATE_JUSTIFIED*: uint64
    ETH1_FOLLOW_DISTANCE*: uint64
    TARGET_AGGREGATORS_PER_COMMITTEE*: uint64
    TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE*: uint64
    RANDOM_SUBNETS_PER_VALIDATOR*: uint64
    EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION*: uint64
    SECONDS_PER_ETH1_BLOCK*: uint64
    DEPOSIT_CHAIN_ID*: uint64
    DEPOSIT_NETWORK_ID*: uint64
    DEPOSIT_CONTRACT_ADDRESS*: Eth1Address
    MIN_DEPOSIT_AMOUNT*: uint64
    MAX_EFFECTIVE_BALANCE*: uint64
    EJECTION_BALANCE*: uint64
    EFFECTIVE_BALANCE_INCREMENT*: uint64
    GENESIS_FORK_VERSION*: Version
    BLS_WITHDRAWAL_PREFIX*: byte
    GENESIS_DELAY*: uint64
    SECONDS_PER_SLOT*: uint64
    MIN_ATTESTATION_INCLUSION_DELAY*: uint64
    SLOTS_PER_EPOCH*: uint64
    MIN_SEED_LOOKAHEAD*: uint64
    MAX_SEED_LOOKAHEAD*: uint64
    EPOCHS_PER_ETH1_VOTING_PERIOD*: uint64
    SLOTS_PER_HISTORICAL_ROOT*: uint64
    SYNC_COMMITTEE_SIZE*: uint64
    SYNC_COMMITTEE_SUBNET_COUNT*: uint64
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY*: uint64
    SHARD_COMMITTEE_PERIOD*: uint64
    MIN_EPOCHS_TO_INACTIVITY_PENALTY*: uint64
    EPOCHS_PER_HISTORICAL_VECTOR*: uint64
    EPOCHS_PER_SLASHINGS_VECTOR*: uint64
    EPOCHS_PER_SYNC_COMMITTEE_PERIOD*: uint64
    HISTORICAL_ROOTS_LIMIT*: uint64
    VALIDATOR_REGISTRY_LIMIT*: uint64
    BASE_REWARD_FACTOR*: uint64
    WHISTLEBLOWER_REWARD_QUOTIENT*: uint64
    PROPOSER_REWARD_QUOTIENT*: uint64
    INACTIVITY_PENALTY_QUOTIENT*: uint64
    INACTIVITY_PENALTY_QUOTIENT_ALTAIR*: uint64
    INACTIVITY_SCORE_BIAS*: uint64
    INACTIVITY_SCORE_RECOVERY_RATE*: uint64
    MIN_SLASHING_PENALTY_QUOTIENT*: uint64
    MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR*: uint64
    MIN_SYNC_COMMITTEE_PARTICIPANTS*: uint64
    PROPORTIONAL_SLASHING_MULTIPLIER*: uint64
    PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR*: uint64
    MAX_PROPOSER_SLASHINGS*: uint64
    MAX_ATTESTER_SLASHINGS*: uint64
    MAX_ATTESTATIONS*: uint64
    MAX_DEPOSITS*: uint64
    MAX_VOLUNTARY_EXITS*: uint64
    DOMAIN_BEACON_PROPOSER*: DomainType
    DOMAIN_BEACON_ATTESTER*: DomainType
    DOMAIN_RANDAO*: DomainType
    DOMAIN_DEPOSIT*: DomainType
    DOMAIN_VOLUNTARY_EXIT*: DomainType
    DOMAIN_SELECTION_PROOF*: DomainType
    DOMAIN_AGGREGATE_AND_PROOF*: DomainType
    DOMAIN_CONTRIBUTION_AND_PROOF*: DomainType
    DOMAIN_SYNC_COMMITTEE*: DomainType
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF*: DomainType

  # The `RestSpec` is a dynamic dictionary that includes version-specific spec
  # constants. New versions may introduce new constants, and remove old ones.
  # The Nimbus validator client fetches the remote spec to determine whether it
  # is connected to a compatible beacon node. For this purpose, it only needs to
  # verify a small set of relevant spec constants. To avoid rejecting a remote
  # spec that includes all of those relevant spec constants, but that does not
  # include all of the locally known spec constants, a separate type is defined
  # that includes just the spec constants relevant for the validator client.
  # Extra spec constants are silently ignored.
  RestSpecVC* = object
    # /!\ Keep in sync with `validator_client/api.nim` > `checkCompatible`.
    MAX_VALIDATORS_PER_COMMITTEE*: uint64
    SLOTS_PER_EPOCH*: uint64
    SECONDS_PER_SLOT*: uint64
    EPOCHS_PER_ETH1_VOTING_PERIOD*: uint64
    SLOTS_PER_HISTORICAL_ROOT*: uint64
    EPOCHS_PER_HISTORICAL_VECTOR*: uint64
    EPOCHS_PER_SLASHINGS_VECTOR*: uint64
    HISTORICAL_ROOTS_LIMIT*: uint64
    VALIDATOR_REGISTRY_LIMIT*: uint64
    MAX_PROPOSER_SLASHINGS*: uint64
    MAX_ATTESTER_SLASHINGS*: uint64
    MAX_ATTESTATIONS*: uint64
    MAX_DEPOSITS*: uint64
    MAX_VOLUNTARY_EXITS*: uint64
    DOMAIN_BEACON_PROPOSER*: DomainType
    DOMAIN_BEACON_ATTESTER*: DomainType
    DOMAIN_RANDAO*: DomainType
    DOMAIN_DEPOSIT*: DomainType
    DOMAIN_VOLUNTARY_EXIT*: DomainType
    DOMAIN_SELECTION_PROOF*: DomainType
    DOMAIN_AGGREGATE_AND_PROOF*: DomainType

  RestDepositContract* = object
    chain_id*: string
    address*: string

  RestBlockInfo* = object
    slot*: Slot
    blck* {.serializedFieldName: "block".}: Eth2Digest

  RestEpochSyncCommittee* = object
    validators*: seq[ValidatorIndex]
    validator_aggregates*: seq[seq[ValidatorIndex]]

  DataEnclosedObject*[T] = object
    data*: T

  DataMetaEnclosedObject*[T] = object
    data*: T
    meta*: JsonNode

  DataRootEnclosedObject*[T] = object
    dependent_root*: Eth2Digest
    data*: T

  ForkedSignedBlockHeader* = object
    slot*: Slot

  ForkedBeaconStateHeader* = object
    genesis_time*: uint64
    genesis_validators_root*: Eth2Digest
    slot*: Slot

  GetBlockResponse* = DataEnclosedObject[phase0.SignedBeaconBlock]
  GetStateResponse* = DataEnclosedObject[phase0.BeaconState]
  GetBlockV2Response* = ForkedSignedBeaconBlock
  GetBlockV2Header* = ForkedSignedBlockHeader
  GetStateV2Response* = ForkedBeaconState
  GetStateV2Header* = ForkedBeaconStateHeader
  GetPhase0StateSszResponse* = phase0.BeaconState
  GetAltairStateSszResponse* = altair.BeaconState
  GetPhase0BlockSszResponse* = phase0.SignedBeaconBlock
  GetAltairBlockSszResponse* = altair.SignedBeaconBlock

  # Types based on the OAPI yaml file - used in responses to requests
  GetAggregatedAttestationResponse* = DataEnclosedObject[Attestation]
  GetAttesterDutiesResponse* = DataRootEnclosedObject[seq[RestAttesterDuty]]
  GetBlockAttestationsResponse* = DataEnclosedObject[seq[Attestation]]
  GetBlockHeaderResponse* = DataEnclosedObject[RestBlockHeaderInfo]
  GetBlockHeadersResponse* = DataEnclosedObject[seq[RestBlockHeaderInfo]]
  GetBlockRootResponse* = DataEnclosedObject[Eth2Digest]
  GetDebugChainHeadsResponse* = DataEnclosedObject[seq[RestChainHead]]
  GetDepositContractResponse* = DataEnclosedObject[RestDepositContract]
  GetEpochCommitteesResponse* = DataEnclosedObject[RestGenesis]
  GetForkScheduleResponse* = DataEnclosedObject[seq[Fork]]
  GetGenesisResponse* = DataEnclosedObject[RestGenesis]
  GetNetworkIdentityResponse* = DataEnclosedObject[RestNetworkIdentity]
  GetPeerCountResponse* = DataMetaEnclosedObject[RestPeerCount]
  GetPeerResponse* = DataMetaEnclosedObject[RestNodePeer]
  GetPeersResponse* = DataMetaEnclosedObject[seq[RestNodePeer]]
  GetPoolAttestationsResponse* = DataEnclosedObject[seq[Attestation]]
  GetPoolAttesterSlashingsResponse* = DataEnclosedObject[seq[AttesterSlashing]]
  GetPoolProposerSlashingsResponse* = DataEnclosedObject[seq[ProposerSlashing]]
  GetPoolVoluntaryExitsResponse* = DataEnclosedObject[seq[SignedVoluntaryExit]]
  GetProposerDutiesResponse* = DataRootEnclosedObject[seq[RestProposerDuty]]
  GetSyncCommitteeDutiesResponse* = DataEnclosedObject[seq[RestSyncCommitteeDuty]]
  GetSpecResponse* = DataEnclosedObject[RestSpec]
  GetSpecVCResponse* = DataEnclosedObject[RestSpecVC]
  GetStateFinalityCheckpointsResponse* = DataEnclosedObject[RestBeaconStatesFinalityCheckpoints]
  GetStateForkResponse* = DataEnclosedObject[Fork]
  GetStateRootResponse* = DataEnclosedObject[Eth2Digest]
  GetStateValidatorBalancesResponse* = DataEnclosedObject[seq[RestValidatorBalance]]
  GetStateValidatorResponse* = DataEnclosedObject[RestValidator]
  GetStateValidatorsResponse* = DataEnclosedObject[seq[RestValidator]]
  GetSyncingStatusResponse* = DataEnclosedObject[RestSyncInfo]
  GetVersionResponse* = DataEnclosedObject[RestNodeVersion]
  GetEpochSyncCommitteesResponse* = DataEnclosedObject[RestEpochSyncCommittee]
  ProduceAttestationDataResponse* = DataEnclosedObject[AttestationData]
  ProduceBlockResponse* = DataEnclosedObject[phase0.BeaconBlock]
  ProduceBlockResponseV2* = ForkedBeaconBlock

func `==`*(a, b: RestValidatorIndex): bool =
  uint64(a) == uint64(b)

func init*(t: typedesc[StateIdent], v: StateIdentType): StateIdent =
  StateIdent(kind: StateQueryKind.Named, value: v)

func init*(t: typedesc[StateIdent], v: Slot): StateIdent =
  StateIdent(kind: StateQueryKind.Slot, slot: v)

func init*(t: typedesc[StateIdent], v: Eth2Digest): StateIdent =
  StateIdent(kind: StateQueryKind.Root, root: v)

func init*(t: typedesc[BlockIdent], v: BlockIdentType): BlockIdent =
  BlockIdent(kind: BlockQueryKind.Named, value: v)

func init*(t: typedesc[BlockIdent], v: Slot): BlockIdent =
  BlockIdent(kind: BlockQueryKind.Slot, slot: v)

func init*(t: typedesc[BlockIdent], v: Eth2Digest): BlockIdent =
  BlockIdent(kind: BlockQueryKind.Root, root: v)

func init*(t: typedesc[ValidatorIdent], v: ValidatorIndex): ValidatorIdent =
  ValidatorIdent(kind: ValidatorQueryKind.Index, index: RestValidatorIndex(v))

func init*(t: typedesc[ValidatorIdent], v: ValidatorPubKey): ValidatorIdent =
  ValidatorIdent(kind: ValidatorQueryKind.Key, key: v)

func init*(t: typedesc[RestBlockInfo],
           v: ForkedTrustedSignedBeaconBlock): RestBlockInfo =
  RestBlockInfo(slot: v.slot(), blck: v.root())

func init*(t: typedesc[RestValidator], index: ValidatorIndex,
           balance: uint64, status: string,
           validator: Validator): RestValidator =
  RestValidator(index: index, balance: Base10.toString(balance),
                status: status, validator: validator)

func init*(t: typedesc[RestValidatorBalance], index: ValidatorIndex,
           balance: uint64): RestValidatorBalance =
  RestValidatorBalance(index: index, balance: Base10.toString(balance))
