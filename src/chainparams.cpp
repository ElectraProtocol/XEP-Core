// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <arith_uint256.h>
#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <hash.h> // for signet block challenge hash
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const std::vector<CScript>& genesisOutputScripts, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const std::vector<CAmount>& genesisRewards)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vin[0].scriptSig = CScript() << OP_0 << nBits << OP_4 << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    for (unsigned int i = 0; i < genesisOutputScripts.size(); i++)
        txNew.vout.emplace_back(genesisRewards[i], genesisOutputScripts[i]);

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

    arith_uint256 hashTarget = arith_uint256().SetCompact(std::min(genesis.nBits, (unsigned)0x1f00ffff));
    /*while (true) {
        arith_uint256 hash = UintToArith256(genesis.GetPoWHash());
        if (hash <= hashTarget) {
            // Found a solution
            printf("genesis block found\n   hash: %s\n target: %s\n   bits: %08x\n  nonce: %u\n", hash.ToString().c_str(), hashTarget.ToString().c_str(), genesis.nBits, genesis.nNonce);
            break;
        }
        genesis.nNonce += 1;
        if ((genesis.nNonce & 0x1ffff) == 0)
            printf("testing nonce: %u\n", genesis.nNonce);
    }*/
    uint256 hash = genesis.GetPoWHash();
    assert(UintToArith256(hash) <= hashTarget);

    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const std::vector<CAmount>& genesisRewards)
{
    const char* pszTimestamp = "Electra Protocol is reborn from block 970621533f14eb1453e36b9862f0b766b4a3e0a98486bd6de2a7d265a22bcb18";
    std::vector<CScript> genesisOutputScripts;
    genesisOutputScripts.emplace_back(CScript() << OP_0 << ParseHex("b7ab61f3f8f36f98177aee6ee0b5b051a9e53471")); // ep1qk74krulc7dhes9m6aehwpdds2x572dr3zne8mz
    genesisOutputScripts.emplace_back(CScript() << OP_0 << ParseHex("978a5064cd1fdf8c2510fe3fcbd65eaa5e98b32d")); // ep1qj799qexdrl0ccfgslcluh4j74f0f3vedatcv0k
    genesisOutputScripts.emplace_back(CScript() << OP_0 << ParseHex("c64fc6777dcffc027ebcfc80d4a91b7304cf798d")); // ep1qce8uvamael7qyl4uljqdf2gmwvzv77vdh852h9
    genesisOutputScripts.emplace_back(CScript() << OP_0 << ParseHex("4536e905b8c5bbc163137fed4cde7d12f0de010f")); // ep1qg5mwjpdcckauzccn0lk5ehnaztcduqg09g6jgu
    genesisOutputScripts.emplace_back(CScript() << OP_0 << ParseHex("5417a551f0989b8a3b00257645cb1e3d2884ca64")); // ep1q2st6250snzdc5wcqy4mytjc7855gfjnyhxyu4f
    assert(genesisOutputScripts.size() == genesisRewards.size());
    return CreateGenesisBlock(pszTimestamp, genesisOutputScripts, nTime, nNonce, nBits, nVersion, genesisRewards);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nBudgetPaymentsStartBlock = std::numeric_limits<int>::max();
        consensus.nPoSStartBlock = 0;
        consensus.nLastPoWBlock = 150000;
        consensus.nMandatoryUpgradeBlock = 150000;
        consensus.nTreasuryPaymentsStartBlock = std::numeric_limits<int>::max();
        consensus.BIP16Exception = uint256{};
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x000000954c02f260a6db02c712557adcb5a7a8a0a9acfd3d3c2b3a427376c56f");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0; // segwit activation height + miner confirmation window
        consensus.powLimit[CBlockHeader::ALGO_POS] = uint256S("000000ffff000000000000000000000000000000000000000000000000000000"); // 0x1e00ffff
        consensus.powLimit[CBlockHeader::ALGO_POW_SHA256] = uint256S("000000ffff000000000000000000000000000000000000000000000000000000"); // 0x1e00ffff
        consensus.nPowTargetTimespan = 12 * 60 * 60; // 12 hours
        consensus.nPowTargetSpacing = 80; // 80-second block spacing - must be divisible by (nStakeTimestampMask+1)
        consensus.nStakeTimestampMask = 0xf; // 16 second time slots
        consensus.nStakeMinDepth = 600;
        consensus.nStakeMinAge = 12 * 60 * 60; // current minimum age for coin age is 12 hours
        consensus.nStakeMaxAge = 30 * 24 * 60 * 60; // 30 days
        consensus.nModifierInterval = 1 * 60; // Modifier interval: time to elapse before new modifier is computed
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = (14 * 24 * 60 * 60 * 95) / (100 * consensus.nPowTargetSpacing); // 95% of the blocks in the past two weeks
        consensus.nMinerConfirmationWindow = 14 * 24 * 60 * 60 / consensus.nPowTargetSpacing; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nTreasuryPaymentsCycleBlocks = 1 * 24 * 60 * 60 / consensus.nPowTargetSpacing; // Once per day
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.mTreasuryPayees.emplace(CScript() << OP_0 << ParseHex("978a5064cd1fdf8c2510fe3fcbd65eaa5e98b32d"), 100); // 10% (full reward) for ep1qj799qexdrl0ccfgslcluh4j74f0f3vedatcv0k
        consensus.nTreasuryRewardPercentage = 10; // 10% of block reward goes to treasury

        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000003e800039d1d6fa46082");
        consensus.defaultAssumeValid = uint256S("0xa11f28829bedd92e634b249e77d4aa6d1dab10075bf19339d02ccc7ae55bb993"); // 150000

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xd1;
        pchMessageStart[1] = 0xba;
        pchMessageStart[2] = 0xe1;
        pchMessageStart[3] = 0xf5;
        nDefaultPort = 16817;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 5;
        m_assumed_chain_state_size = 1;

        std::vector<CAmount> genesisRewards; // premine
        genesisRewards.emplace_back(27000000000 * COIN); // 27 billion
        genesisRewards.emplace_back(1500000000 * COIN); // 1.5 billion
        genesisRewards.emplace_back(500000000 * COIN); // 0.5 billion
        genesisRewards.emplace_back(500000000 * COIN); // 0.5 billion
        genesisRewards.emplace_back(500000000 * COIN); // 0.5 billion
        genesis = CreateGenesisBlock(1609246800, 10543997, UintToArith256(consensus.powLimit[CBlockHeader::ALGO_POW_SHA256]).GetCompact(), 1, genesisRewards);
        consensus.hashGenesisBlock = genesis.GetHash();
        //printf("Merkle hash mainnet: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //printf("Genesis hash mainnet: %s\n", consensus.hashGenesisBlock.ToString().c_str());
        assert(genesis.hashMerkleRoot == uint256S("0x951ef417a7e31855adad366ad777b3a4608a7f50679baa54e81a28904097a26f"));
        assert(consensus.hashGenesisBlock == uint256S("0x000000954c02f260a6db02c712557adcb5a7a8a0a9acfd3d3c2b3a427376c56f"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("seed01.electraprotocol.eu");
        vSeeds.emplace_back("seed02.electraprotocol.eu");
        vSeeds.emplace_back("seed03.electraprotocol.eu");
        vSeeds.emplace_back("seed04.electraprotocol.eu");
        vSeeds.emplace_back("seed05.electraprotocol.eu");
        vSeeds.emplace_back("seed06.electraprotocol.eu");
        vSeeds.emplace_back("seed07.electraprotocol.eu");
        vSeeds.emplace_back("seed08.electraprotocol.eu");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,55);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,137);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,162);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "ep";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                { 0, uint256S("000000954c02f260a6db02c712557adcb5a7a8a0a9acfd3d3c2b3a427376c56f")},
                { 50000, uint256S("505286a87781aabbb6cfc7a9b735ffacd8ce73bc06ed17dae546cafe4ca3e7a3")},
                { 100000, uint256S("88e536f2f4dad78b2177694d3b269f2145a5087d677f393a9980a300f746b6bf")},
                { 150000, uint256S("a11f28829bedd92e634b249e77d4aa6d1dab10075bf19339d02ccc7ae55bb993")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 30720 a11f28829bedd92e634b249e77d4aa6d1dab10075bf19339d02ccc7ae55bb993
            /* nTime    */ 1621012016,
            /* nTxCount */ 305352,
            /* dTxRate  */ 0.02558495472683127,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nBudgetPaymentsStartBlock = std::numeric_limits<int>::max();
        consensus.nPoSStartBlock = 0;
        consensus.nLastPoWBlock = std::numeric_limits<int>::max();
        consensus.nMandatoryUpgradeBlock = 0;
        consensus.nTreasuryPaymentsStartBlock = 200;
        consensus.BIP16Exception = uint256{};
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x000000954c02f260a6db02c712557adcb5a7a8a0a9acfd3d3c2b3a427376c56f");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0; // segwit activation height + miner confirmation window
        consensus.powLimit[CBlockHeader::ALGO_POS] = uint256S("000000ffff000000000000000000000000000000000000000000000000000000"); // 0x1e00ffff
        consensus.powLimit[CBlockHeader::ALGO_POW_SHA256] = uint256S("000000ffff000000000000000000000000000000000000000000000000000000"); // 0x1e00ffff
        consensus.nPowTargetTimespan = 12 * 60 * 60; // 12 hours
        consensus.nPowTargetSpacing = 80; // 80-second block spacing - must be divisible by (nStakeTimestampMask+1)
        consensus.nStakeTimestampMask = 0xf; // 16 second time slots
        consensus.nStakeMinDepth = 100;
        consensus.nStakeMinAge = 2 * 60 * 60; // testnet min age is 2 hours
        consensus.nStakeMaxAge = 30 * 24 * 60 * 60; // 30 days
        consensus.nModifierInterval = 1 * 60; // Modifier interval: time to elapse before new modifier is computed
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = (14 * 24 * 60 * 60 * 75) / (100 * consensus.nPowTargetSpacing); // 75% for testchains
        consensus.nMinerConfirmationWindow = 14 * 24 * 60 * 60 / consensus.nPowTargetSpacing; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nTreasuryPaymentsCycleBlocks = 24 * 6 * 60 / consensus.nPowTargetSpacing; // Ten times per day
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.mTreasuryPayees.emplace(CScript() << OP_0 << ParseHex("978a5064cd1fdf8c2510fe3fcbd65eaa5e98b32d"), 100); // 10% (full reward) for ep1qj799qexdrl0ccfgslcluh4j74f0f3vedatcv0k
        consensus.nTreasuryRewardPercentage = 10; // 10% of block reward goes to treasury

        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.defaultAssumeValid = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"); // 1864000

        pchMessageStart[0] = 0xdb;
        pchMessageStart[1] = 0xb1;
        pchMessageStart[2] = 0xc9;
        pchMessageStart[3] = 0xa7;
        nDefaultPort = 18317;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 5;
        m_assumed_chain_state_size = 1;

        std::vector<CAmount> genesisRewards; // premine
        genesisRewards.emplace_back(27000000000 * COIN); // 27 billion
        genesisRewards.emplace_back(1500000000 * COIN); // 1.5 billion
        genesisRewards.emplace_back(500000000 * COIN); // 0.5 billion
        genesisRewards.emplace_back(500000000 * COIN); // 0.5 billion
        genesisRewards.emplace_back(500000000 * COIN); // 0.5 billion
        genesis = CreateGenesisBlock(1609246800, 10543997, UintToArith256(consensus.powLimit[CBlockHeader::ALGO_POW_SHA256]).GetCompact(), 1, genesisRewards);
        consensus.hashGenesisBlock = genesis.GetHash();
        //printf("Merkle hash testnet: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //printf("Genesis hash testnet: %s\n", consensus.hashGenesisBlock.ToString().c_str());
        assert(genesis.hashMerkleRoot == uint256S("0x951ef417a7e31855adad366ad777b3a4608a7f50679baa54e81a28904097a26f"));
        assert(consensus.hashGenesisBlock == uint256S("0x000000954c02f260a6db02c712557adcb5a7a8a0a9acfd3d3c2b3a427376c56f"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("seed01.electraprotocol.eu");
        vSeeds.emplace_back("seed02.electraprotocol.eu");
        vSeeds.emplace_back("seed03.electraprotocol.eu");
        vSeeds.emplace_back("seed04.electraprotocol.eu");
        vSeeds.emplace_back("seed05.electraprotocol.eu");
        vSeeds.emplace_back("seed06.electraprotocol.eu");
        vSeeds.emplace_back("seed07.electraprotocol.eu");
        vSeeds.emplace_back("seed08.electraprotocol.eu");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,141);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "te";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, uint256S("000000954c02f260a6db02c712557adcb5a7a8a0a9acfd3d3c2b3a427376c56f")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 000000000000006433d1efec504c53ca332b64963c425395515b01977bd7b3b0
            /* nTime    */ 0,
            /* nTxCount */ 0,
            /* dTxRate  */ 0,
        };
    }
};

/**
 * Signet
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const ArgsManager& args) {
        std::vector<uint8_t> bin;
        vSeeds.clear();

        if (!args.IsArgSet("-signetchallenge")) {
            bin = ParseHex("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
            vSeeds.emplace_back("seed01.electraprotocol.eu");
            vSeeds.emplace_back("seed02.electraprotocol.eu");
            vSeeds.emplace_back("seed03.electraprotocol.eu");
            vSeeds.emplace_back("seed04.electraprotocol.eu");
            vSeeds.emplace_back("seed05.electraprotocol.eu");
            vSeeds.emplace_back("seed06.electraprotocol.eu");
            vSeeds.emplace_back("seed07.electraprotocol.eu");
            vSeeds.emplace_back("seed08.electraprotocol.eu");
            //vSeeds.emplace_back("v7ajjeirttkbnt32wpy3c6w3emwnfr3fkla7hpxcfokr3ysd3kqtzmqd.onion:38333");

            consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
            consensus.defaultAssumeValid = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"); // 9434
            m_assumed_blockchain_size = 1;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                // Data from RPC: getchaintxstats 30720 0000002a1de0f46379358c1fd09906f7ac59adf3712323ed90eb59e4c183c020
                /* nTime    */ 0,
                /* nTxCount */ 0,
                /* dTxRate  */ 0,
            };
        } else {
            const auto signet_challenge = args.GetArgs("-signetchallenge");
            if (signet_challenge.size() != 1) {
                throw std::runtime_error(strprintf("%s: -signetchallenge cannot be multiple values.", __func__));
            }
            bin = ParseHex(signet_challenge[0]);

            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", signet_challenge[0]);
        }

        if (args.IsArgSet("-signetseednode")) {
            vSeeds = args.GetArgs("-signetseednode");
        }

        strNetworkID = CBaseChainParams::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nBudgetPaymentsStartBlock = std::numeric_limits<int>::max();
        consensus.nPoSStartBlock = 0;
        consensus.nLastPoWBlock = std::numeric_limits<int>::max();
        consensus.nMandatoryUpgradeBlock = 0;
        consensus.nTreasuryPaymentsStartBlock = 200;
        consensus.BIP16Exception = uint256{};
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.nPowTargetTimespan = 12 * 60 * 60; // 12 hours
        consensus.nPowTargetSpacing = 80; // 80-second block spacing - must be divisible by (nStakeTimestampMask+1)
        consensus.nStakeTimestampMask = 0xf; // 16 second time slots
        consensus.nStakeMinDepth = 600;
        consensus.nStakeMinAge = 12 * 60 * 60; // current minimum age for coin age is 12 hours
        consensus.nStakeMaxAge = 30 * 24 * 60 * 60; // 30 days
        consensus.nModifierInterval = 1 * 60; // Modifier interval: time to elapse before new modifier is computed
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = (14 * 24 * 60 * 60 * 95) / (100 * consensus.nPowTargetSpacing); // 95% of the blocks in the past two weeks
        consensus.nMinerConfirmationWindow = 14 * 24 * 60 * 60 / consensus.nPowTargetSpacing; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nTreasuryPaymentsCycleBlocks = 1 * 24 * 60 * 60 / consensus.nPowTargetSpacing; // Once per day
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit[CBlockHeader::ALGO_POS] = uint256S("000000ffff000000000000000000000000000000000000000000000000000000"); // 0x1e00ffff
        consensus.powLimit[CBlockHeader::ALGO_POW_SHA256] = uint256S("00000377ae000000000000000000000000000000000000000000000000000000"); // 0x1e0377ae
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.mTreasuryPayees.emplace(CScript() << OP_0 << ParseHex("978a5064cd1fdf8c2510fe3fcbd65eaa5e98b32d"), 100); // 10% (full reward) for ep1qj799qexdrl0ccfgslcluh4j74f0f3vedatcv0k
        consensus.nTreasuryRewardPercentage = 10; // 10% of block reward goes to treasury

        // message start is defined as the first 4 bytes of the sha256d of the block script
        CHashWriter h(SER_DISK, 0);
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        memcpy(pchMessageStart, hash.begin(), 4);

        nDefaultPort = 38317;
        nPruneAfterHeight = 1000;

        std::vector<CAmount> genesisRewards; // premine
        genesisRewards.emplace_back(27000000000 * COIN); // 27 billion
        genesisRewards.emplace_back(1500000000 * COIN); // 1.5 billion
        genesisRewards.emplace_back(500000000 * COIN); // 0.5 billion
        genesisRewards.emplace_back(500000000 * COIN); // 0.5 billion
        genesisRewards.emplace_back(500000000 * COIN); // 0.5 billion
        genesis = CreateGenesisBlock(1609246800, 2078674, UintToArith256(consensus.powLimit[CBlockHeader::ALGO_POW_SHA256]).GetCompact(), 1, genesisRewards);
        consensus.hashGenesisBlock = genesis.GetHash();
        //printf("Merkle hash signet: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //printf("Genesis hash signet: %s\n", consensus.hashGenesisBlock.ToString().c_str());
        assert(genesis.hashMerkleRoot == uint256S("0x31583424f19f97bb2987c57ae2a826e9772cea828f367e99875261eaa82d60ad"));
        assert(consensus.hashGenesisBlock == uint256S("0x000000b6e751fad208e0e1d39c83e3fe896482bf039699c724df5deec6e8d30b"));

        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,141);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "te";

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nBudgetPaymentsStartBlock = std::numeric_limits<int>::max();
        consensus.nPoSStartBlock = 0;
        consensus.nLastPoWBlock = std::numeric_limits<int>::max();
        consensus.nMandatoryUpgradeBlock = 0;
        consensus.nTreasuryPaymentsStartBlock = 30;
        consensus.BIP16Exception = uint256{};
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.CSVHeight = 432; // CSV activated on regtest (Used in rpc activation tests)
        consensus.SegwitHeight = 0; // SEGWIT is always activated on regtest unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit[CBlockHeader::ALGO_POS] = uint256S("7fffff0000000000000000000000000000000000000000000000000000000000"); // 0x207fffff
        consensus.powLimit[CBlockHeader::ALGO_POW_SHA256] = uint256S("7fffff0000000000000000000000000000000000000000000000000000000000"); // 0x207fffff
        consensus.nPowTargetTimespan = 1 * 60 * 60; // 1 hour
        consensus.nPowTargetSpacing = 80; // 80-second block spacing - must be divisible by (nStakeTimestampMask+1)
        consensus.nStakeTimestampMask = 0x3; // 4 second time slots
        consensus.nStakeMinDepth = 0;
        consensus.nStakeMinAge = 1 * 60; // regtest min age is 1 minute
        consensus.nStakeMaxAge = 30 * 24 * 60 * 60; // 30 days
        consensus.nModifierInterval = 1 * 60; // Modifier interval: time to elapse before new modifier is computed
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = (24 * 60 * 60 * 75) / (100 * consensus.nPowTargetSpacing); // 75% for testchains
        consensus.nMinerConfirmationWindow = 24 * 60 * 60 / consensus.nPowTargetSpacing; // Faster than normal for regtest (one day instead of two weeks)
        consensus.nTreasuryPaymentsCycleBlocks = 20;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        consensus.mTreasuryPayees.emplace(CScript() << OP_0 << ParseHex("978a5064cd1fdf8c2510fe3fcbd65eaa5e98b32d"), 100); // 10% (full reward) for ep1qj799qexdrl0ccfgslcluh4j74f0f3vedatcv0k
        consensus.nTreasuryRewardPercentage = 10; // 10% of block reward goes to treasury

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xc5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        std::vector<CAmount> genesisRewards; // premine
        genesisRewards.emplace_back(27000000000 * COIN); // 27 billion
        genesisRewards.emplace_back(1500000000 * COIN); // 1.5 billion
        genesisRewards.emplace_back(500000000 * COIN); // 0.5 billion
        genesisRewards.emplace_back(500000000 * COIN); // 0.5 billion
        genesisRewards.emplace_back(500000000 * COIN); // 0.5 billion
        genesis = CreateGenesisBlock(1609246800, 14201, UintToArith256(consensus.powLimit[CBlockHeader::ALGO_POW_SHA256]).GetCompact(), 1, genesisRewards);
        consensus.hashGenesisBlock = genesis.GetHash();
        //printf("Merkle hash regtest: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //printf("Genesis hash regtest: %s\n", consensus.hashGenesisBlock.ToString().c_str());
        assert(genesis.hashMerkleRoot == uint256S("0x74d37252db3a2e1960cb4d62da34954ab26d39e431a8b77afe3dd31d8ddc96b3"));
        assert(consensus.hashGenesisBlock == uint256S("0x00005c7509dcd261eea59d1cbe054f8ad6adb0b783ea4169d22ddba5b3fc6b50"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256S("00005c7509dcd261eea59d1cbe054f8ad6adb0b783ea4169d22ddba5b3fc6b50")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,141);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "eprt";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (args.IsArgSet("-segwitheight")) {
        int64_t height = args.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return std::unique_ptr<CChainParams>(new CMainParams());
    } else if (chain == CBaseChainParams::TESTNET) {
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    } else if (chain == CBaseChainParams::SIGNET) {
        return std::unique_ptr<CChainParams>(new SigNetParams(args));
    } else if (chain == CBaseChainParams::REGTEST) {
        return std::unique_ptr<CChainParams>(new CRegTestParams(args));
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(gArgs, network);
}
