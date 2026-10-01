#define BOOST_TEST_MODULE BasicTest
#include <boost/test/tools/old/interface.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/test/unit_test_suite.hpp>

#include "include/TcpSocket.hpp"

BOOST_AUTO_TEST_CASE(test_constructor)
{
  TcpSocket::Socket socket{};

  socket.wait_for_a_packet();
}
