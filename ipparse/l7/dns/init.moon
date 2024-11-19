subclass, Packet = do
  _ = require"ipparse"
  _.subclass, _.Packet
Question = require"ipparse.l7.dns.question"
RR = require"ipparse.l7.dns.rr"

local DNS
DNS = subclass Packet, {
  __name: "DNS"

  iana_port: 53

  types: require"ipparse.l7.dns.types"

  _get_id: => @short 0

  _get_qr: => @bit 2, 1

  _get_opcode: => @byte(2) >> 3 & 0xf

  _get_aa: => @bit 2, 6

  _get_tc: => @bit 2, 7

  _get_rd: => @bit 2, 8

  _get_ra: => @bit 3, 1

  _get_z: => @nibble(3) & 0x7

  _get_rcode: => @nibble 3, 2

  _get_qdcount: => @short 4

  _get_ancount: => @short 6

  _get_nscount: => @short 8

  _get_arcount: => @short 10

  _get_question: => @questions[1]  -- cf. RFC 9619

  _get_questions: =>
    questions = {}
    off = 0
    for i = 1, @qdcount
      q = Question skb: @skb, off: @off + @data_off + off
      questions[i] = q
      off += q.length
    questions

  rrs: (off, count) =>
    rrs = {}
    for i = 1, count
      r = RR skb: @skb, :off
      rrs[i] = r
      off += r.length
    rrs

  _get_answers: =>
    q = @questions[#@questions]
    @rrs q.off+q.length, @ancount

  _get_nameservers: =>
    a = @answers[#@answers]
    DNS.rrs @, a.off+a.length, @nscount

  _get_additional: =>
    ns = @nameservers[#@nameservers]
    DNS.rrs @, ns.off+ns.length, @arcount

  data_off: 12
}

DNS

