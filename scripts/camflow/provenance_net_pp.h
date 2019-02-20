# 1 "./camflow/provenance_net.h"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 325 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "./camflow/provenance_net.h" 2
# 36 "./camflow/provenance_net.h"
static inline struct provenance *get_socket_inode_provenance(struct socket *sock)
{
 struct inode *inode = SOCK_INODE(sock);
 struct provenance *iprov = NULL;

 if (inode)
  iprov = get_inode_provenance(inode, false);
 return iprov;
}
# 57 "./camflow/provenance_net.h"
static inline struct provenance *get_sk_inode_provenance(struct sock *sk)
{
 struct socket *sock = sk->sk_socket;

 if (!sock)
  return NULL;
 return get_socket_inode_provenance(sock);
}
# 73 "./camflow/provenance_net.h"
static inline struct provenance *get_sk_provenance(struct sock *sk)
{
 struct provenance *prov = sk->sk_provenance;

 return prov;
}
# 89 "./camflow/provenance_net.h"
static inline struct provenance *get_socket_provenance(struct socket *sock)
{
 struct sock *sk = sock->sk;

 if (!sk)
  return NULL;
 return get_sk_provenance(sk);
}
# 109 "./camflow/provenance_net.h"
static inline void __extract_tcp_info(struct sk_buff *skb,
          struct iphdr *ih,
          int offset,
          struct packet_identifier *id)
{
 struct tcphdr _tcph;
 struct tcphdr *th;
 int tcpoff;

 if (ntohs(ih->frag_off) & IP_OFFSET)
  return;
 tcpoff = offset + (ih->ihl * 4);
 th = skb_header_pointer(skb, tcpoff, sizeof(_tcph), &_tcph);
 if (!th)
  return;
 id->snd_port = th->source;
 id->rcv_port = th->dest;
 id->seq = th->seq;
}
# 138 "./camflow/provenance_net.h"
static inline void __extract_udp_info(struct sk_buff *skb,
          struct iphdr *ih,
          int offset,
          struct packet_identifier *id)
{
 struct udphdr _udph;
 struct udphdr *uh;
 int udpoff;

 if (ntohs(ih->frag_off) & IP_OFFSET)
  return;
 udpoff = offset + (ih->ihl * 4);
 uh = skb_header_pointer(skb, udpoff, sizeof(_udph), &_udph);
 if (!uh)
  return;
 id->snd_port = uh->source;
 id->rcv_port = uh->dest;
}
# 167 "./camflow/provenance_net.h"
static inline unsigned int provenance_parse_skb_ipv4(struct sk_buff *skb, union prov_elt *prov)
{
 struct packet_identifier *id;
 int offset;
 struct iphdr _iph;
 struct iphdr *ih;

 offset = skb_network_offset(skb);
 ih = skb_header_pointer(skb, offset, sizeof(_iph), &_iph);
 if (!ih)
  return -EINVAL;

 if ((ih->ihl * 4) < sizeof(_iph))
  return -EINVAL;

 memset(prov, 0, sizeof(union prov_elt));
 id = &packet_identifier(prov);

 id->type = ENT_PACKET;

 id->id = ih->id;
 id->snd_ip = ih->saddr;
 id->rcv_ip = ih->daddr;
 id->protocol = ih->protocol;
 prov->pck_info.length = ih->tot_len;

 switch (ih->protocol) {
 case IPPROTO_TCP:
  __extract_tcp_info(skb, ih, offset, id);
  break;
 case IPPROTO_UDP:
  __extract_udp_info(skb, ih, offset, id);
  break;
 default:
  break;
 }
 return 0;
}

struct ipv4_filters {
 struct list_head list;
 struct prov_ipv4_filter filter;
};

extern struct list_head ingress_ipv4filters;
extern struct list_head egress_ipv4filters;
# 229 "./camflow/provenance_net.h"
static inline int prov_ipv4_whichOP(struct list_head *filters, int ip, int port)
{
 struct list_head *listentry, *listtmp;
 struct ipv4_filters *tmp;

 while(listentry, listtmp, filters) {
  tmp = list_entry(listentry, ipv4_filters, list);
  if ((tmp->filter.mask & ip) == (tmp->filter.mask & tmp->filter.ip))
   if (tmp->filter.port == 0 || tmp->filter.port == port)
    return tmp->filter.op;
 }
 return 0;
}
# 254 "./camflow/provenance_net.h"
static inline int prov_ipv4_delete(struct list_head *filters, struct ipv4_filters *f)
{
 struct list_head *listentry, *listtmp;
 struct ipv4_filters *tmp;

 while(listentry, listtmp, filters) {
  tmp = list_entry(listentry, ipv4_filters, list);
  if (tmp->filter.mask == f->filter.mask &&
      tmp->filter.ip == f->filter.ip &&
      tmp->filter.port == f->filter.port) {
   list_del(listentry);
   kfree(tmp);
   return 0;
  }
 }
 return 0;
}
# 283 "./camflow/provenance_net.h"
static inline int prov_ipv4_add_or_update(struct list_head *filters, struct ipv4_filters *f)
{
 struct list_head *listentry, *listtmp;
 struct ipv4_filters *tmp;

 while(listentry, listtmp, filters) {
  tmp = list_entry(listentry, ipv4_filters, list);
  if (tmp->filter.mask == f->filter.mask &&
      tmp->filter.ip == f->filter.ip &&
      tmp->filter.port == f->filter.port) {
   tmp->filter.op |= f->filter.op;
   return 0;
  }
 }
 list_add_tail(&(f->list), filters);
 return 0;
}
# 317 "./camflow/provenance_net.h"
static int record_address(struct sockaddr *address, int addrlen, struct provenance *prov)
{
 union long_prov_elt *addr_info;
 int rc = 0;

 if (provenance_is_name_recorded(prov_elt(prov)) || !provenance_is_recorded(prov_elt(prov)))
  return 0;
 addr_info = alloc_long_provenance(ENT_ADDR);
 if (!addr_info) {
  rc = -ENOMEM;
  goto out;
 }
 addr_info->address_info.length = addrlen;
 memcpy(&(addr_info->address_info.addr), address, addrlen);

 rc = record_relation(RL_NAMED, addr_info, prov_entry(prov), NULL, 0);
 set_name_recorded(prov_elt(prov));
out:
 free_long_provenance(addr_info);
 return rc;
}

static void record_packet_content(struct sk_buff *skb,
        struct provenance *pckprov)
{
 union long_prov_elt *cnt;

 cnt = alloc_long_provenance(ENT_PCKCNT);
 if (!cnt)
  return;

 cnt->pckcnt_info.length = skb_end_offset(skb);
 if (cnt->pckcnt_info.length >= PATH_MAX) {
  cnt->pckcnt_info.truncated = PROV_TRUNCATED;
  memcpy(cnt->pckcnt_info.content, skb->head, PATH_MAX);
 } else
  memcpy(cnt->pckcnt_info.content, skb->head, cnt->pckcnt_info.length);
 record_relation(RL_PCK_CNT, cnt, prov_entry(pckprov), NULL, 0);
 free_long_provenance(cnt);
}
