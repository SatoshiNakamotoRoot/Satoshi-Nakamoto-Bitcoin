#include <addresstype.h>
#include <boost/test/unit_test.hpp>
#include <common/sv2_messages.h>
#include <interfaces/mining.h>
#include <node/sv2_template_provider.h>
#include <node/transaction.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/transaction_utils.h>
#include <util/sock.h>
#include <util/strencodings.h>

#include <memory>

BOOST_FIXTURE_TEST_SUITE(sv2_template_provider_tests, TestChain100Setup)

/**
  * A class for testing the Template Provider. Each TPTester encapsulates a
  * Sv2TemplateProvider (the one being tested) as well as a Sv2Cipher
  * to act as the other side.
  */
class TPTester {
private:
    std::unique_ptr<Sv2Transport> m_peer_transport; //!< Transport for peer
    // Sockets that will be returned by the TP listening socket Accept() method.
    std::shared_ptr<DynSock::Queue> m_tp_accepted_sockets{std::make_shared<DynSock::Queue>()};
    std::shared_ptr<DynSock::Pipes> m_current_client_pipes;

public:
    std::unique_ptr<Sv2TemplateProvider> m_tp; //!< Sv2TemplateProvider being tested

    TPTester(interfaces::Mining& mining)
    {
        m_tp = std::make_unique<Sv2TemplateProvider>(mining);

        CreateSock = [this](int, int, int) -> std::unique_ptr<Sock> {
            // This will be the bind/listen socket from m_tp. It will
            // create other sockets via its Accept() method.
            return std::make_unique<DynSock>(std::make_shared<DynSock::Pipes>(), m_tp_accepted_sockets);
        };

        BOOST_REQUIRE(m_tp->Start(Sv2TemplateProviderOptions { .port = 18448 }));
    }

    void SendPeerBytes()
    {
        const auto& [data, more, _m_message_type] = m_peer_transport->GetBytesToSend(/*have_next_message=*/false);
        BOOST_REQUIRE(data.size() > 0);

        // Schedule data to be returned by the next Recv() call from
        // Sv2Connman on the socket it has accepted.
        m_current_client_pipes->recv.PushBytes(data.data(), data.size());
        m_peer_transport->MarkBytesSent(data.size());
    }

    // Have the peer receive and process bytes:
    size_t PeerReceiveBytes()
    {
        uint8_t buf[0x10000];
        // Get the data that has been written to the accepted socket with Send() by TP.
        // Wait until the bytes appear in the "send" pipe.
        ssize_t n;
        for (;;) {
            n = m_current_client_pipes->send.GetBytes(buf, sizeof(buf), 0);
            if (n != -1 || errno != EAGAIN) {
                break;
            }
            UninterruptibleSleep(50ms);
        }

        // Inform client's transport that some bytes have been received (sent by TP).
        if (n > 0) {
            Span<const uint8_t> s(buf, n);
            BOOST_REQUIRE(m_peer_transport->ReceivedBytes(s));
        }

        return n;
    }

    /* Create a new client and perform handshake */
    void handshake()
    {
        m_peer_transport.reset();

        auto peer_static_key{GenerateRandomKey()};
        m_peer_transport = std::make_unique<Sv2Transport>(std::move(peer_static_key), m_tp->m_authority_pubkey);

        // Have Sv2Connman's listen socket's Accept() simulate a newly arrived connection.
        m_current_client_pipes = std::make_shared<DynSock::Pipes>();
        m_tp_accepted_sockets->Push(
            std::make_unique<DynSock>(m_current_client_pipes, std::make_shared<DynSock::Queue>()));

        // Flush transport for handshake part 1
        SendPeerBytes();

        // Read handshake part 2 from transport
        BOOST_REQUIRE_EQUAL(PeerReceiveBytes(), Sv2HandshakeState::HANDSHAKE_STEP2_SIZE);
    }

    void receiveMessage(Sv2NetMsg& msg)
    {
        // Client encrypts message and puts it on the transport:
        CSerializedNetMsg net_msg{std::move(msg)};
        BOOST_REQUIRE(m_peer_transport->SetMessageToSend(net_msg));
        SendPeerBytes();
    }

    Sv2NetMsg SetupConnectionMsg()
    {
        std::vector<uint8_t> bytes{
            0x02,                                                 // protocol
            0x02, 0x00,                                           // min_version
            0x02, 0x00,                                           // max_version
            0x01, 0x00, 0x00, 0x00,                               // flags
            0x07, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30,       // endpoint_host
            0x61, 0x21,                                           // endpoint_port
            0x07, 0x42, 0x69, 0x74, 0x6d, 0x61, 0x69, 0x6e,       // vendor
            0x08, 0x53, 0x39, 0x69, 0x20, 0x31, 0x33, 0x2e, 0x35, // hardware_version
            0x1c, 0x62, 0x72, 0x61, 0x69, 0x69, 0x6e, 0x73, 0x2d, 0x6f, 0x73, 0x2d, 0x32, 0x30,
            0x31, 0x38, 0x2d, 0x30, 0x39, 0x2d, 0x32, 0x32, 0x2d, 0x31, 0x2d, 0x68, 0x61, 0x73,
            0x68, // firmware
            0x10, 0x73, 0x6f, 0x6d, 0x65, 0x2d, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x75,
            0x75, 0x69, 0x64, // device_id
        };

        return node::Sv2NetMsg{node::Sv2MsgType::SETUP_CONNECTION, std::move(bytes)};
    }

    size_t GetBlockTemplateCount()
    {
        LOCK(m_tp->m_tp_mutex);
        return m_tp->GetBlockTemplates().size();
    }
};

BOOST_AUTO_TEST_CASE(client_tests)
{
    auto mining{interfaces::MakeMining(m_node)};
    TPTester tester{*mining};

    tester.handshake();

    // After the handshake the client must send a SetupConnection message to the
    // Template Provider.

    tester.handshake();
    BOOST_TEST_MESSAGE("Handshake done, send SetupConnectionMsg");

    node::Sv2NetMsg setup{tester.SetupConnectionMsg()};
    tester.receiveMessage(setup);
    // SetupConnection.Success is 6 bytes
    BOOST_REQUIRE_EQUAL(tester.PeerReceiveBytes(), SV2_HEADER_ENCRYPTED_SIZE + 6 + Poly1305::TAGLEN);

    // There should be no block templates before any client gave us their coinbase
    // output data size:
    BOOST_REQUIRE(tester.GetBlockTemplateCount() == 0);

    std::vector<uint8_t> coinbase_output_max_additional_size_bytes{
        0x01, 0x00, 0x00, 0x00
    };
    node::Sv2NetMsg msg{node::Sv2MsgType::COINBASE_OUTPUT_DATA_SIZE, std::move(coinbase_output_max_additional_size_bytes)};
    BOOST_TEST_MESSAGE("The reply should be NewTemplate and SetNewPrevHash");
    tester.receiveMessage(msg);
    BOOST_REQUIRE_EQUAL(tester.PeerReceiveBytes(), 2 * SV2_HEADER_ENCRYPTED_SIZE + 91 + 80 + 2 * Poly1305::TAGLEN);

    // There should now be one template
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 1);

    // Move mock time by at least DEFAULT_SV2_INTERVAL
    // If the mempool doesn't change, no new template is generated.
    SetMockTime(GetMockTime() + std::chrono::seconds{DEFAULT_SV2_INTERVAL});
    // Briefly wait for the timer in ThreadSv2Handler and block creation
    UninterruptibleSleep(std::chrono::milliseconds{200});
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 1);

    // Create a transaction with a large fee
    size_t tx_size;
    CKey key = GenerateRandomKey();
    CScript locking_script = GetScriptForDestination(PKHash(key.GetPubKey()));
    // Don't hold on to the transaction
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(m_node.mempool->size(), 0);

        auto mtx = CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                        /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                        /*output_destination=*/locking_script,
                                                        /*output_amount=*/CAmount(49 * COIN), /*submit=*/true);
        CTransactionRef tx = MakeTransactionRef(mtx);

        // Get serialized transaction size
        DataStream ss;
        ss << TX_WITH_WITNESS(tx);
        tx_size = ss.size();

        BOOST_REQUIRE_EQUAL(m_node.mempool->size(), 1);
    }

    // Move mock time by at least DEFAULT_SV2_INTERVAL
    SetMockTime(GetMockTime() + std::chrono::seconds{DEFAULT_SV2_INTERVAL});

    // Briefly wait for the timer in ThreadSv2MempoolHandler and block creation
    UninterruptibleSleep(std::chrono::milliseconds{200});

    // Get the latest template id
    uint64_t template_id = 0;
    {
        LOCK(tester.m_tp->m_tp_mutex);
        for (auto& t : tester.m_tp->GetBlockTemplates()) {
            if (t.first > template_id) {
                template_id = t.first;
            }
        }
    }

    // Expect our peer to receive a NewTemplate message
    // This time it should contain the 32 byte prevhash (unchanged)
    constexpr size_t expected_len = SV2_HEADER_ENCRYPTED_SIZE + 91 + 32 + Poly1305::TAGLEN;
    BOOST_REQUIRE_EQUAL(tester.PeerReceiveBytes(), expected_len);

    // Have the peer send us RequestTransactionData
    // We should reply with RequestTransactionData.Success
    node::Sv2NetHeader req_tx_data_header{node::Sv2MsgType::REQUEST_TRANSACTION_DATA, 8};
    DataStream ss;
    ss << template_id;
    std::vector<unsigned char> template_id_bytes;
    template_id_bytes.resize(8);
    ss >> MakeWritableByteSpan(template_id_bytes);

    msg = node::Sv2NetMsg{req_tx_data_header.m_msg_type, std::move(template_id_bytes)};
    tester.receiveMessage(msg);
    const size_t template_id_size = 8;
    const size_t excess_data_size = 2 + 32;
    size_t tx_list_size = 2 + 3 + tx_size;
    BOOST_REQUIRE_EQUAL(tester.PeerReceiveBytes(), SV2_HEADER_ENCRYPTED_SIZE + template_id_size + excess_data_size + tx_list_size + Poly1305::TAGLEN);
    {
        LOCK(cs_main);

        // RBF the transaction with with > DEFAULT_SV2_FEE_DELTA
        CreateValidMempoolTransaction(/*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0,
                                                    /*input_height=*/0, /*input_signing_key=*/coinbaseKey,
                                                    /*output_destination=*/locking_script,
                                                    /*output_amount=*/CAmount(48 * COIN), /*submit=*/true);

        BOOST_REQUIRE_EQUAL(m_node.mempool->size(), 1);
    }

    // Move mock time by at least DEFAULT_SV2_INTERVAL
    SetMockTime(GetMockTime() + std::chrono::seconds{DEFAULT_SV2_INTERVAL});

    // Briefly wait for the timer in ThreadSv2Handler and block creation
    UninterruptibleSleep(std::chrono::milliseconds{200});

    // Check that there's a new template
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 3);

    // Wait a bit more for macOS native CI
    UninterruptibleSleep(std::chrono::milliseconds{1000});

    // Expect our peer to receive a NewTemplate message
    BOOST_REQUIRE_EQUAL(tester.PeerReceiveBytes(), SV2_HEADER_ENCRYPTED_SIZE + 91 + 32 + Poly1305::TAGLEN);

    // Have the peer send us RequestTransactionData for the old template
    // We should reply with RequestTransactionData.Success, and the original
    // (replaced) transaction
    tester.receiveMessage(msg);
    tx_list_size = 2 + 3 + tx_size;
    BOOST_REQUIRE_EQUAL(tester.PeerReceiveBytes(), SV2_HEADER_ENCRYPTED_SIZE + template_id_size + excess_data_size + tx_list_size + Poly1305::TAGLEN);

    // Create a new block
    mineBlocks(1);

    // We should send out another NewTemplate and SetNewPrevHash
    // The new template contains the new prevhash.
    BOOST_REQUIRE_EQUAL(tester.PeerReceiveBytes(), 2 * SV2_HEADER_ENCRYPTED_SIZE + 91 + 32 + 80 + 2 * Poly1305::TAGLEN);
    // The SetNewPrevHash message is redundant
    // TODO: don't send it?
    // Background: in the future we want to send an empty or optimistic template
    //             before a block is found, so ASIC's can preload it. We would
    //             then immedidately send a SetNewPrevHash message when there's
    //             a new block, and construct a better template _after_ that.

    // Templates are briefly preserved
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 4);

    // Do not provide transactions for stale templates
    // TODO

    // But do allow SubmitSolution
    // TODO

    // Until after some time
    SetMockTime(GetMockTime() + std::chrono::seconds{15});
    UninterruptibleSleep(std::chrono::milliseconds{100});
    BOOST_REQUIRE_EQUAL(tester.GetBlockTemplateCount(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
