// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2022 John "ComputerCraftr" Studnicka
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
//#include <logging.h>
#include <primitives/block.h>
#include <sync.h>
#include <uint256.h>

#include <mutex>

static Mutex cs_target_cache;

// peercoin: find last block index up to pindex
static inline const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, const bool fProofOfStake)
{
    while (pindex && pindex->IsProofOfStake() != fProofOfStake && pindex->pprev) {
        pindex = pindex->pprev;
    }
    return pindex;
}

static inline const CBlockIndex* GetLastBlockIndexForAlgo(const CBlockIndex* pindex, const int algo)
{
    while (pindex && CBlockHeader::GetAlgoType(pindex->nVersion) != algo && pindex->pprev) {
        pindex = pindex->pprev;
    }
    return pindex;
}

static inline const CBlockIndex* GetASERTReferenceBlockForAlgo(const CBlockIndex* pindex, const int nASERTStartHeight, const int algo)
{
    if (!pindex)
        return pindex;

    while (pindex->nHeight >= nASERTStartHeight) {
        const CBlockIndex* pprev = GetLastBlockIndexForAlgo(pindex->pprev, algo);
        if (pprev) {
            pindex = pprev;
        } else {
            break;
        }
    }
    return pindex;
}

// Note that calling this function as part of the difficulty calculation for every block results in a time complexity of O(n^2)
// with respect to the number of blocks in the chain as it must count back to the reference block each time it is called while syncing
/*static inline const CBlockIndex* GetASERTReferenceBlockAndHeightForAlgo(const CBlockIndex* pindex, const uint32_t nProofOfWorkLimit, const int nASERTStartHeight, const int algo, uint32_t& nBlocksPassed)
{
    nBlocksPassed = 1; // Account for the ASERT reference block here

    if (!pindex)
        return pindex;

    while (pindex->nHeight >= nASERTStartHeight) {
        const CBlockIndex* pprev = GetLastBlockIndexForAlgo(pindex->pprev, algo);
        if (pprev) {
            pindex = pprev;
        } else {
            break;
        }

        //if (pindex->nBits != (nProofOfWorkLimit - 1))
        nBlocksPassed++;
    }
    return pindex;
}*/

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const int algo = CBlockHeader::GetAlgoType(pblock->nVersion);
    const uint32_t nProofOfWorkLimit = UintToArith256(params.powLimit[algo == -1 ? CBlockHeader::AlgoType::ALGO_POW_SHA256 : algo]).GetCompactBase256();
    if (pindexLast == nullptr || params.fPowNoRetargeting)
        return nProofOfWorkLimit;

    if (params.fPowAllowMinDifficultyBlocks && algo != -1) {
        // Special difficulty rule:
        // If the new block's timestamp is more than 30 minutes (be careful to ensure this is at least twice the actual PoW target spacing to avoid interfering with retargeting)
        // then allow mining of a min-difficulty block.
        const CBlockIndex* pindexPrev = GetLastBlockIndexForAlgo(pindexLast, algo);
        if (pindexPrev->nHeight > 10 && pblock->GetBlockTime() > pindexPrev->GetBlockTime() + (30*60))
            return (nProofOfWorkLimit - 1);
        if (pindexPrev->pprev && pindexPrev->nBits == (nProofOfWorkLimit - 1)) {
            // Return the block before the last non-special-min-difficulty-rules-block
            const CBlockIndex* pindex = pindexPrev;
            while (pindex->pprev && (pindex->nBits == (nProofOfWorkLimit - 1) || CBlockHeader::GetAlgoType(pindex->nVersion) != algo))
                pindex = pindex->pprev;
            const CBlockIndex* pprev = GetLastBlockIndexForAlgo(pindex->pprev, algo);
            if (pprev && pprev->nHeight > 10) {
                // Don't return pprev->nBits if it is another min-difficulty block; instead return pindex->nBits
                if (pprev->nBits != (nProofOfWorkLimit - 1))
                    return pprev->nBits;
                else
                    return pindex->nBits;
            }
        }
    }

    return AverageTargetASERT(pindexLast, pblock, params);
}

unsigned int GetNextWorkRequiredXEP(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit[CBlockHeader::AlgoType::ALGO_POW_SHA256]).GetCompactBase256();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit[CBlockHeader::AlgoType::ALGO_POW_SHA256]);
    arith_uint256 bnNew;
    bnNew.SetCompactBase256(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompactBase256();
}

unsigned int WeightedTargetExponentialMovingAverage(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const int algo = CBlockHeader::GetAlgoType(pblock->nVersion);
    const bool fAlgoMissing = algo == -1;
    const bool fProofOfStake = pblock->IsProofOfStake();
    const arith_uint256 bnPowLimit = fAlgoMissing ? UintToArith256(params.powLimit[fProofOfStake ? CBlockHeader::AlgoType::ALGO_POS : CBlockHeader::AlgoType::ALGO_POW_SHA256]) : UintToArith256(params.powLimit[algo]);
    const uint32_t nProofOfWorkLimit = bnPowLimit.GetCompactBase256();
    if (pindexLast == nullptr)
        return nProofOfWorkLimit; // genesis block

    const CBlockIndex* pindexPrev = fAlgoMissing ? GetLastBlockIndex(pindexLast, fProofOfStake) : GetLastBlockIndexForAlgo(pindexLast, algo);
    if (pindexPrev->pprev == nullptr)
        return nProofOfWorkLimit; // first block

    const CBlockIndex* pindexPrevPrev = fAlgoMissing ? GetLastBlockIndex(pindexPrev->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindexPrev->pprev, algo);
    if (pindexPrevPrev->pprev == nullptr)
        return nProofOfWorkLimit; // second block

    int nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime(); // Difficulty for PoW and PoS are calculated separately

    arith_uint256 bnNew;
    bnNew.SetCompactBase256(pindexPrev->nBits);
    int nTargetSpacing = params.nPowTargetSpacing;
    const uint32_t nTargetTimespan = params.nPowTargetTimespan;
    //nTargetSpacing *= 2; // 160 second block time for PoW + 160 second block time for PoS = 80 second effective block time
    if (!fProofOfStake) {
        //nTargetSpacing *= (CBlockHeader::AlgoType::ALGO_COUNT - 1); // Multiply by the number of PoW algos
        nTargetSpacing = 10 * 60; // PoW spacing is 10 minutes
    }
    const int nInterval = nTargetTimespan / (nTargetSpacing * 2); // alpha_reciprocal = (N(SMA) + 1) / 2 for same "center of mass" as SMA

    // nActualSpacing must be restricted as to not produce a negative number below
    // The functionality of this if statement has been moved directly into the calculation of the numerator with the call to std::max
    //if (nActualSpacing <= -((nInterval - 1) * nTargetSpacing))
        //nActualSpacing = -((nInterval - 1) * nTargetSpacing) + 1;

    const uint32_t numerator = std::max((nInterval - 1) * nTargetSpacing + nActualSpacing, 1);
    const uint32_t denominator = nInterval * nTargetSpacing;

    // Keep in mind the order of operations and integer division here - this is why the *= operator cannot be used, as it could cause overflow or integer division to occur
    arith_uint512 bnNew512 = arith_uint512(bnNew) * numerator / denominator; // For WTEMA: next_target = prev_target * (nInterval - 1 + prev_solvetime/target_solvetime) / nInterval
    bnNew = bnNew512.trim256();

    if (bnNew512 > arith_uint512(bnPowLimit) || bnNew == arith_uint256())
        return nProofOfWorkLimit;

    return bnNew.GetCompactRoundedBase256();
}

unsigned int AverageTargetASERT(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    const int algo = CBlockHeader::GetAlgoType(pblock->nVersion);
    const bool fAlgoMissing = algo == -1;
    const bool fProofOfStake = pblock->IsProofOfStake();
    const arith_uint256 bnPowLimit = fAlgoMissing ? UintToArith256(params.powLimit[fProofOfStake ? CBlockHeader::AlgoType::ALGO_POS : CBlockHeader::AlgoType::ALGO_POW_SHA256]) : UintToArith256(params.powLimit[algo]);
    const uint32_t nProofOfWorkLimit = bnPowLimit.GetCompactBase256();
    uint32_t nTargetSpacing = params.nPowTargetSpacing;
    //nTargetSpacing *= 2; // 160 second block time for PoW + 160 second block time for PoS = 80 second effective block time
    if (!fProofOfStake) {
        //nTargetSpacing *= (CBlockHeader::AlgoType::ALGO_COUNT - 1); // Multiply by the number of PoW algos
        nTargetSpacing = 10 * 60; // PoW spacing is 10 minutes
    }

    if (pindexLast == nullptr)
        return nProofOfWorkLimit; // genesis block

    const CBlockIndex* pindexPrev = fAlgoMissing ? GetLastBlockIndex(pindexLast, fProofOfStake) : GetLastBlockIndexForAlgo(pindexLast, algo);
    if (pindexPrev->pprev == nullptr)
        return nProofOfWorkLimit; // first block

    const CBlockIndex* pindexPrevPrev = fAlgoMissing ? GetLastBlockIndex(pindexPrev->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindexPrev->pprev, algo);
    if (pindexPrevPrev->pprev == nullptr)
        return nProofOfWorkLimit; // second block

    constexpr uint32_t nASERTStartHeight = 0;
    // In the future, it may be a good idea to switch this from height based to a fixed time window
    const uint32_t nASERTBlockTargetsToAverage = 4 * params.nPowTargetTimespan / nTargetSpacing; // Average the past 2 days' worth of block targets

    const uint32_t nHeight = pindexLast->nHeight + 1;
    if (nHeight < nASERTStartHeight)
        return WeightedTargetExponentialMovingAverage(pindexLast, pblock, params);

    const uint32_t nBlocksPassed = (fProofOfStake ? pindexLast->nHeightPoS : pindexLast->nHeightPoW) + 1; // Account for the ASERT reference block (when it is the genesis block at height 0) by adding one to the height

    // Using a static variable concurrently in this context is safe and will not cause a race condition during initialization because C++11 guarantees that static variables will be initialized exactly once
    static const CBlockIndex* const pindexReferenceBlocks[CBlockHeader::AlgoType::ALGO_COUNT] = {
        GetASERTReferenceBlockForAlgo(pindexPrev, nASERTStartHeight, CBlockHeader::AlgoType::ALGO_POS),
        GetASERTReferenceBlockForAlgo(pindexPrev, nASERTStartHeight, CBlockHeader::AlgoType::ALGO_POW_SHA256),
    };

    const CBlockIndex* const pindexReferenceBlock = fAlgoMissing ? pindexReferenceBlocks[fProofOfStake ? CBlockHeader::AlgoType::ALGO_POS : CBlockHeader::AlgoType::ALGO_POW_SHA256] : pindexReferenceBlocks[algo];
    const CBlockIndex* const pindexReferenceBlockPrev = fAlgoMissing ? GetLastBlockIndex(pindexReferenceBlock->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindexReferenceBlock->pprev, algo);

    // Use reference block's parent block's timestamp unless it is the genesis (not using the prev timestamp here would put us permanently one block behind schedule)
    int64_t refBlockTimestamp = pindexReferenceBlockPrev ? pindexReferenceBlockPrev->GetBlockTime() : (pindexReferenceBlock->GetBlockTime() - nTargetSpacing);

    // The reference timestamp must be divisible by (nStakeTimestampMask+1) or else the PoS block emission will never be exactly on schedule
    if (fProofOfStake) {
        while ((refBlockTimestamp & params.nStakeTimestampMask) != 0)
            refBlockTimestamp++;
    }

    const int64_t nTimeDiff = pindexPrev->GetBlockTime() - refBlockTimestamp;
    const uint32_t nHeightDiff = nBlocksPassed; //pindexPrev->nHeight + 1 - pindexReferenceBlock->nHeight;
    arith_uint256 refBlockTarget;

    // We don't want to recalculate the average of several days' worth of block targets here every single time, so instead we cache the average and start height
    constexpr bool fUseCache = true;
    {
        LOCK(cs_target_cache);

        static arith_uint256 refBlockTargetCache GUARDED_BY(cs_target_cache);
        static int nTargetCacheHeight GUARDED_BY(cs_target_cache) = -2;
        static int nTargetCacheAlgo GUARDED_BY(cs_target_cache) = CBlockHeader::AlgoType::ALGO_COUNT;

        if (nASERTBlockTargetsToAverage > 0 && nHeight >= nASERTStartHeight + nASERTBlockTargetsToAverage && nHeightDiff >= nASERTBlockTargetsToAverage) {
            if (!fUseCache || nTargetCacheHeight != static_cast<int>(nHeightDiff / nASERTBlockTargetsToAverage) || nTargetCacheAlgo != algo || refBlockTargetCache == arith_uint256() || fAlgoMissing) {
                const uint32_t nBlocksToSkip = nHeightDiff % nASERTBlockTargetsToAverage;
                const CBlockIndex* pindex = pindexPrev;
                //LogPrintf("nBlocksToSkip = %u\n", nBlocksToSkip);

                for (unsigned int i = 0; i < nBlocksToSkip; i++) {
                    pindex = fAlgoMissing ? GetLastBlockIndex(pindex->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindex->pprev, algo);
                }
                //LogPrintf("begin pindex->nHeight = %i\n", pindex->nHeight);

                //unsigned int nBlocksAveraged = 0;
                for (int i = 0; i < static_cast<int>(nASERTBlockTargetsToAverage); i++) {
                    if (pindex->nBits != (nProofOfWorkLimit - 1) || !params.fPowAllowMinDifficultyBlocks) { // Don't add min difficulty targets to the average
                        arith_uint256 bnTarget = arith_uint256().SetCompactBase256(pindex->nBits);
                        refBlockTarget += bnTarget / nASERTBlockTargetsToAverage;
                        //nBlocksAveraged++;
                        //if (pindex->GetBlockHash() == params.hashGenesisBlock)
                            //LogPrintf("Averaging genesis block target\n");
                    } else
                        i--; // Average one more block to make up for the one we skipped
                    pindex = fAlgoMissing ? GetLastBlockIndex(pindex->pprev, fProofOfStake) : GetLastBlockIndexForAlgo(pindex->pprev, algo);
                    if (!pindex)
                        break;
                }
                //LogPrintf("nBlocksAveraged = %u\n", nBlocksAveraged);
                //assert(nBlocksAveraged == nASERTBlockTargetsToAverage);
                //if (pindex)
                    //LogPrintf("end pindex->nHeight = %i\n", pindex->nHeight);
                if (fUseCache) {
                    refBlockTargetCache = refBlockTarget;
                    nTargetCacheHeight = nHeightDiff / nASERTBlockTargetsToAverage;
                    nTargetCacheAlgo = algo;
                    //LogPrintf("Set average target cache at nHeight = %u with algo = %i\n", nHeight, algo);
                }
            } else {
                refBlockTarget = refBlockTargetCache;
                //LogPrintf("Using average target cache at nHeight = %u with algo = %i\n", nHeight, algo);
            }
        } else {
            if (fUseCache && !fAlgoMissing) {
                if (nTargetCacheHeight != -1 || nTargetCacheAlgo != algo || refBlockTargetCache == arith_uint256()) {
                    refBlockTargetCache = arith_uint256().SetCompactBase256(pindexReferenceBlock->nBits);
                    nTargetCacheHeight = -1;
                    nTargetCacheAlgo = algo;
                    //LogPrintf("Set ref target cache at nHeight = %u with algo = %i\n", nHeight, algo);
                }
                refBlockTarget = refBlockTargetCache;
            } else
                refBlockTarget = arith_uint256().SetCompactBase256(pindexReferenceBlock->nBits);
        }
    }

    //LogPrintf("nHeight = %u, algo = %i, refBlockTarget = %s\n", nHeight, algo, refBlockTarget.ToString().c_str());
    arith_uint256 bnNew(refBlockTarget);
    const int64_t dividend = nTimeDiff - nTargetSpacing * nHeightDiff;
    const bool fPositive = dividend >= 0;
    const uint32_t divisor = params.nPowTargetTimespan; // Must be positive
    const int exponent = dividend / divisor; // Note: this integer division rounds down positive and rounds up negative numbers via truncation, but the truncated fractional part is handled by the approximation below
    const uint32_t remainder = (fPositive ? dividend : -dividend) % divisor; // Must be positive
    // We are using uint512 rather than uint64_t here because a nPowTargetTimespan of more than 3 days in the divisor may cause the following cubic approximation to overflow a uint64_t
    arith_uint512 numerator(1);
    arith_uint512 denominator(1);
    // Alternatively, ensure that the nPowTargetTimespan (divisor) is small enough such that (2*2*2) * (4 + 11 + 35 + 50) * (divisor)^3 < (2^64 - 1) which is the uint64_t maximum value to leave some room and make overflow extremely unlikely
    //assert(divisor <= (3 * 24 * 60 * 60));
    // Keep in mind that a large exponent due to being extremely far ahead or behind schedule, especially in case of reviving an abandoned chain, will also lead to overflowing the numerator, so a less accurate approximation should be used in this case
    //uint64_t numerator = 1;
    //uint64_t denominator = 1;

    //LogPrintf("nHeight = %u, algo = %i is %s schedule, nTimeDiff = %li, ideal = %u, exponent = %i\n", nHeight, algo, fPositive ? "behind" : "ahead of", nTimeDiff, nTargetSpacing * nHeightDiff, exponent);
    if (fPositive) {
        if (exponent > 0) {
            // Left shifting the numerator is equivalent to multiplying it by a power of 2
            numerator <<= exponent;
        }

        if (remainder != 0) { // Approximate 2^x with (4x^3+11x^2+35x+50)/50 for 0<x<1 (must be equal to 1 at x=0 and equal to 2 at x=1 to avoid discontinuities) - note: x+1 and (3x^2+7x+10)/10 are also decent and less complicated approximations
            //numerator *= remainder + divisor; // x+1
            //denominator *= divisor;

            const arith_uint512 bnDivisor(divisor);
            const arith_uint512 bnRemainder(remainder);
            numerator = numerator * ((4 * bnRemainder*bnRemainder*bnRemainder) + (11 * bnRemainder*bnRemainder * bnDivisor) + (35 * bnRemainder * bnDivisor*bnDivisor) + (50 * bnDivisor*bnDivisor*bnDivisor));
            denominator = denominator * (50 * bnDivisor*bnDivisor*bnDivisor);
            //numerator = numerator * ((4lu * remainder*remainder*remainder) + (11lu * remainder*remainder * divisor) + (35lu * remainder * divisor*divisor) + (50lu * divisor*divisor*divisor));
            //denominator = denominator * (50lu * divisor*divisor*divisor);
        }
    } else {
        if (exponent < 0) {
            // Left shifting the denominator is equivalent to multiplying it by a power of 2
            denominator <<= -exponent;
        }

        if (remainder != 0) { // Approximate 2^x with (4x^3+11x^2+35x+50)/50 for 0<x<1 (must be equal to 1 at x=0 and equal to 2 at x=1 to avoid discontinuities) - note: x+1 and (3x^2+7x+10)/10 are also decent and less complicated approximations
            //numerator *= divisor;
            //denominator *= remainder + divisor; // x+1

            const arith_uint512 bnDivisor(divisor);
            const arith_uint512 bnRemainder(remainder);
            numerator = numerator * (50 * bnDivisor*bnDivisor*bnDivisor);
            denominator = denominator * ((4 * bnRemainder*bnRemainder*bnRemainder) + (11 * bnRemainder*bnRemainder * bnDivisor) + (35 * bnRemainder * bnDivisor*bnDivisor) + (50 * bnDivisor*bnDivisor*bnDivisor));
            //numerator = numerator * (50lu * divisor*divisor*divisor);
            //denominator = denominator * ((4lu * remainder*remainder*remainder) + (11lu * remainder*remainder * divisor) + (35lu * remainder * divisor*divisor) + (50lu * divisor*divisor*divisor));
        }
    }

    // Keep in mind the order of operations and integer division here - this is why the *= operator cannot be used, as it could cause overflow or integer division to occur
    arith_uint512 bnNew512(arith_uint512(bnNew) * numerator / denominator);
    //arith_uint512 bnNew512(arith_uint512(bnNew) * arith_uint512(numerator) / arith_uint512(denominator));
    bnNew = bnNew512.trim256();

    //LogPrintf("numerator = %s\n", numerator.ToString().c_str());
    //LogPrintf("denominator = %s\n", denominator.ToString().c_str());
    //LogPrintf("numerator = %lu\n", numerator);
    //LogPrintf("denominator = %lu\n", denominator);
    //LogPrintf("10000 * 2^(%li/%u) = %s\n", dividend, divisor, arith_uint512((10000 * arith_uint512(numerator)) / arith_uint512(denominator)).trim256().ToString().c_str());
    if (bnNew512 > arith_uint512(bnPowLimit) || bnNew == arith_uint256())
        return nProofOfWorkLimit;

    return bnNew.GetCompactRoundedBase256();
}

bool CheckProofOfWork(const uint256& hash, const unsigned int nBits, const int algo, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompactBase256(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || algo < -1 || algo == CBlockHeader::AlgoType::ALGO_POS || algo >= CBlockHeader::AlgoType::ALGO_COUNT || bnTarget > UintToArith256(params.powLimit[algo == -1 ? CBlockHeader::AlgoType::ALGO_POW_SHA256 : algo]))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
