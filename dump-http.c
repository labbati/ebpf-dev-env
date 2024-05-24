#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP 6
#define ETH_HLEN 14

struct Key
{
	u32 src_ip;				 // source ip
	u32 dst_ip;				 // destination ip
	unsigned short src_port; // source port
	unsigned short dst_port; // destination port
};

struct Leaf
{
	int timestamp; // timestamp in ns
	int location;  // 0: beginning, 1: headers, 2: payload
};

const int BEGINNING = 0;
const int HEADERS = 1;
const int PAYLOAD = 2;

// BPF_TABLE(map_type, key_type, leaf_type, table_name, num_entry)
// map <Key, Leaf>
// tracing sessions having same Key(dst_ip, src_ip, dst_port,src_port)
BPF_HASH(sessions, struct Key, struct Leaf, 1024);

/*eBPF program.
  Filter IP and TCP packets, having payload not empty
  and containing "HTTP", "GET", "POST"  as first bytes of payload.
  AND ALL the other packets having same (src_ip,dst_ip,src_port,dst_port)
  this means belonging to the same "session"
  this additional check avoids url truncation, if url is too long
  userspace script, if necessary, reassembles urls split in 2 or more packets.
  if the program is loaded as PROG_TYPE_SOCKET_FILTER
  and attached to a socket
  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
int http_filter(struct __sk_buff *skb)
{
	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	// filter IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800))
	{
		goto DROP;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	// filter TCP packets (ip next protocol = 0x06)
	if (ip->nextp != IP_TCP)
	{
		goto DROP;
	}

	u32 tcp_header_length = 0;
	u32 ip_header_length = 0;
	u32 payload_offset = 0;
	u32 payload_length = 0;
	struct Key key;
	struct Leaf zero = {0, BEGINNING};

	// calculate ip header length
	// value to multiply * 4
	// e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
	ip_header_length = ip->hlen << 2; // SHL 2 -> *4 multiply

	// check ip header length against minimum
	if (ip_header_length < sizeof(*ip))
	{
		goto DROP;
	}

	// shift cursor forward for dynamic ip header size
	void *_ = cursor_advance(cursor, (ip_header_length - sizeof(*ip)));

	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

	// retrieve ip src/dest and port src/dest of current packet
	// and save it into struct Key
	key.dst_ip = ip->dst;
	key.src_ip = ip->src;
	key.dst_port = tcp->dst_port;
	key.src_port = tcp->src_port;

	// calculate tcp header length
	// value to multiply *4
	// e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 byte = 20 byte
	tcp_header_length = tcp->offset << 2; // SHL 2 -> *4 multiply

	// calculate payload offset and length
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
	payload_length = ip->tlen - ip_header_length - tcp_header_length;

	struct Leaf *lookup_leaf = sessions.lookup(&key);

	// http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
	// minimum length of http request is always geater than 7 bytes
	// avoid invalid access memory
	// include empty payload
	if (payload_length < 7 && !lookup_leaf)
	{
		goto DROP;
	}

	// We are not interested in the payload
	if (lookup_leaf && lookup_leaf->location == PAYLOAD)
	{
		goto DROP;
	}

	// load first 7 byte of payload into p (payload_array)
	// direct access to skb not allowed
	unsigned long p[7];
	int i = 0;
	for (i = 0; i < 7; i++)
	{
		p[i] = load_byte(skb, payload_offset + i);
	}

	// find a match with an HTTP message
	// HTTP
	if (
		!lookup_leaf &&
			((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) ||
		((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) || ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) || ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) || ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) || ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')))
	{
		// // let's see if this is all headers or the payloads starts
		// for (int idx = 0; idx < payload_length - 4; idx++)
		// {
		// 	if (p[idx] == 13 && p[idx + 1] == 10 && p[idx + 2] == 13 && p[idx + 3] == 10)
		// 	{
		// 		// CRLFCRLF (separation between headers and body)
		// 	}
		// }
		// goto HEADERS_MATCH;
		zero.location = HEADERS;
		lookup_leaf = sessions.lookup_or_try_init(&key, &zero);
	}

	if (!lookup_leaf)
	{
		goto DROP;
	}

	// Here we need to check byte by byte, because we might have mixed headers + payload
	int minus_0 = 0;
	int minus_1 = 0;
	int minus_2 = 0;
	int minus_3 = 0;
	for (int idx = 0; idx < payload_length - 4; idx++)
	{
		minus_1 = minus_0;
		minus_2 = minus_1;
		minus_3 = minus_2;
		minus_0 = load_byte(skb, payload_offset + i);

		if (minus_3 == 13 && minus_2 == 10 && minus_1 == 13 && minus_0 == 10)
		{
			zero.location = PAYLOAD;
			sessions.update(&key, &zero);
			break;
		}
	}

	goto KEEP;

	// // check if packet belong to an active HTTP session

	// // if (lookup_leaf->location == HEADERS) {}

	// if (lookup_leaf)
	// {
	// 	// send packet to userspace
	// 	goto KEEP;
	// }
	// goto DROP;

// keep the packet and send it to userspace returning -1
// HEADERS_MATCH:
// if not already present, insert into map <Key, Leaf>
// struct Leaf *lookup_leaf = sessions.lookup_or_try_init(&key, &zero);
// if (lookup_leaf)
// {
// 	lookup_leaf->location = HEADERS;
// }

// send packet to userspace returning -1
KEEP:
	return -1;

// drop the packet returning 0 (the packed is "dropped" in the sense it does not go to userspace, it is like if
// this ebpf program was not installed)
DROP:
	return 0;
}
