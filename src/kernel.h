// Copyright (c) 2012-2020 The Peercoin developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2018-2020 John "ComputerCraftr" Studnicka
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef PEERCOIN_KERNEL_H
#define PEERCOIN_KERNEL_H

#include <arith_uint256.h>
#include <coins.h>
#include <primitives/transaction.h> // CTransaction(Ref)
#include <streams.h>

class CBlockIndex;
class BlockValidationState;
class CBlockHeader;
class CBlock;


// MODIFIER_INTERVAL_RATIO:
// ratio of group interval length between the last group and the first group
static const int MODIFIER_INTERVAL_RATIO = 3;

// Compute the hash modifier for proof-of-stake
bool ComputeNextStakeModifier(const CBlockIndex* pindexCurrent, uint64_t& nStakeModifier, bool& fGeneratedStakeModifier);
uint256 ComputeStakeModifierV2(const CBlockIndex* pindexPrev, const uint256& kernel);
uint64_t ComputeStakeModifierV3(const CBlockIndex* pindexPrev, const uint256& kernel);

// Check whether stake kernel meets hash target
// Sets hashProofOfStake on success return
uint256 stakeHash(const unsigned int& nTimeTx, CDataStream& ss, const unsigned int& prevoutIndex, const uint256& prevoutHash, const unsigned int& nTimeBlockFrom, bool fNewOrder);
bool GetKernelStakeModifier(const CBlockIndex* pindexPrev, const uint256& hashBlockFrom, unsigned int nTimeTx, const Consensus::Params& params, uint64_t& nStakeModifier, uint256& nStakeModifierV2, int& nStakeModifierHeight, int64_t& nStakeModifierTime, bool fPrintProofOfStake);
bool CheckStakeKernelHash(const unsigned int& nBits, const CBlockIndex* pindexPrev, const CBlockIndex* pindexFrom, const CTxOut& prevTxOut, const unsigned int& nTimeTxPrev, const COutPoint& prevout, unsigned int& nTimeTx, unsigned int nHashDrift, bool fCheck, uint256& hashProofOfStake, bool fPrintProofOfStake = false);

// Check kernel hash target and coinstake signature
// Sets hashProofOfStake on success return
bool CheckProofOfStake(BlockValidationState& state, const CCoinsViewCache& view, const CBlockIndex* pindexPrev, const CTransactionRef& tx, const unsigned int& nBits, unsigned int nTimeTx, uint256& hashProofOfStake);

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64_t nTimeBlock, int64_t nTimeTx);

// Get stake modifier checksum
//unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex);

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum);

bool IsSuperMajority(unsigned int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck);

// peercoin: entropy bit for stake modifier if chosen by modifier
unsigned int GetStakeEntropyBit(const CBlock& block);

#endif // PEERCOIN_KERNEL_H
