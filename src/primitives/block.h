// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2018-2021 John "ComputerCraftr" Studnicka
// Copyright (c) 2018-2020 The Simplicity developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    static const uint32_t FIRST_FORK_VERSION = 5;
    uint32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CBlockHeader()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce); }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    // peercoin: two types of block: proof-of-work or proof-of-stake
    bool IsProofOfStake() const
    {
        // nNonce == 0 for PoS blocks
        return (nVersion & VERSION_ALGO_MASK) == VERSION_ALGO_POS || (nVersion < FIRST_FORK_VERSION && nNonce == 0);
    }

    bool IsProofOfWork() const
    {
        return (nVersion & VERSION_ALGO_POW_MASK) || (nVersion < FIRST_FORK_VERSION && nNonce != 0);
    }

    enum AlgoType {
        ALGO_POS = 0,
        ALGO_POW_SHA256 = 1,
        ALGO_COUNT
    };

    enum AlgoFlag {
        VERSION_ALGO_POS = 1<<29,
        VERSION_ALGO_POW_SHA256 = 2<<29,
        VERSION_ALGO_MASK = 7<<29,
        VERSION_ALGO_POW_MASK = 6<<29
    };

    static int GetAlgoType(uint32_t version)
    {
        switch (version & VERSION_ALGO_MASK) {
        case VERSION_ALGO_POS:
            return ALGO_POS;
        case VERSION_ALGO_POW_SHA256:
            return ALGO_POW_SHA256;
        default:
            return -1;
        }
    }

    static uint32_t GetAlgoFlag(int type)
    {
        switch (type) {
        case ALGO_POS:
            return VERSION_ALGO_POS;
        case ALGO_POW_SHA256:
            return VERSION_ALGO_POW_SHA256;
        default:
            return FIRST_FORK_VERSION;
        }
    }

    uint256 GetHash() const;
    uint256 GetPoWHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // peercoin: block signature - signed by coin base txout[0]'s owner
    std::vector<unsigned char> vchBlockSig;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITEAS(CBlockHeader, obj);
        READWRITE(obj.vtx);
        if (obj.vtx.size() > 1 && obj.vtx[1]->IsCoinStake())
            READWRITE(obj.vchBlockSig);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
        vchBlockSig.clear();
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }

    // peercoin: two types of block: proof-of-work or proof-of-stake
    /*bool IsProofOfStake() const
    {
        return (vtx.size() > 1 && vtx[1]->IsCoinStake());
    }

    bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }*/

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
