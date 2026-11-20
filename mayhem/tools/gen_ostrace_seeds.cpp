// Writes ostrace log files (the format extract-ostrace reads) using the bragi-generated
// encoders of protocols/ostrace/ostrace.bragi. Used once to produce the committed seeds in
// mayhem/extract_ostrace/testsuite and the golden input of mayhem/tests/ostrace; not part of
// the build. Usage: gen_ostrace_seeds <out-dir>
#include <bragi/helpers-all.hpp>
#include <bragi/helpers-std.hpp>
#include <ostrace.bragi.hpp>

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

using Bytes = std::vector<char>;

template<typename M>
static void putRecord(Bytes &out, M &msg) {
	Bytes head(8), tail(msg.size_of_tail());
	if(!bragi::write_head_tail(msg, head, tail))
		throw 1;
	out.insert(out.end(), head.begin(), head.end());
	out.insert(out.end(), tail.begin(), tail.end());
}

static void putFrame(Bytes &out, uint64_t source, uint64_t seq, uint64_t writer,
		uint64_t first, uint64_t num, const Bytes &page) {
	managarm::ostrace::Frame f;
	f.set_source(source); f.set_seq(seq); f.set_size(page.size());
	f.set_writer(writer); f.set_first_event(first); f.set_num_events(num);
	Bytes head(bragi::head_size<managarm::ostrace::Frame>);
	if(!bragi::write_head_only(f, head))
		throw 1;
	out.insert(out.end(), head.begin(), head.end());
	out.insert(out.end(), page.begin(), page.end());
}

static Bytes page(uint64_t evId, const char *evName, uint64_t ts, uint64_t v, std::string buf) {
	Bytes p;
	managarm::ostrace::Definition d1; d1.set_id(evId); d1.set_name(evName); putRecord(p, d1);
	managarm::ostrace::Definition d2; d2.set_id(evId + 1); d2.set_name("len"); putRecord(p, d2);
	managarm::ostrace::Definition d3; d3.set_id(evId + 2); d3.set_name("data"); putRecord(p, d3);
	managarm::ostrace::EventRecord e; e.set_id(evId); e.set_ts(ts); putRecord(p, e);
	managarm::ostrace::UintAttribute u; u.set_id(evId + 1); u.set_v(v); putRecord(p, u);
	managarm::ostrace::BufferAttribute b; b.set_id(evId + 2);
	b.set_buffer(std::vector<uint8_t>(buf.begin(), buf.end())); putRecord(p, b);
	managarm::ostrace::EndOfRecord eor; putRecord(p, eor);
	return p;
}

static void write(const std::string &path, const Bytes &b) {
	std::ofstream f(path, std::ios::binary);
	f.write(b.data(), b.size());
}

int main(int argc, char **argv) {
	std::string dir = argc > 1 ? argv[1] : ".";
	Bytes one;
	putFrame(one, 1, 0, 0, 0, 1, page(10, "posix.read", 1000, 42, "hello"));
	write(dir + "/one_event.ostrace", one);

	Bytes multi;
	putFrame(multi, 0, 0, 0, 0, 1, page(1, "thor.irq", 500, 7, "ab"));
	putFrame(multi, 2, 1, 3, 0, 1, page(5, "netserver.rx", 1500, 60, "frame"));
	putFrame(multi, 0, 3, 0, 2, 1, page(1, "thor.irq", 2500, 8, "cd"));
	write(dir + "/multi_writer.ostrace", multi);
	return 0;
}
