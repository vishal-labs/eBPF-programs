#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/in6.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);     
    __type(value, __u64); 
} ssh_ip_map SEC(".maps");


SEC("sk_lookup")
int ssh_func(struct bpf_sk_lookup *ctx){
        if(&ctx->local_port  == __bpf_constant_htons(22)){
                __u32 ip_val = &ctx->remote_ip4;
                __u64 *val, count = 1;
                val = bpf_map_lookup_table(&ssh_ip_map, &ip_val);
                if val{
                        __sync_fetch_and_add(val,1);
                }
                else{
                        bpf_map_update_elem(&ssh_ip_map, &ip_val, &count, BPF_ANY);
                }
                return SK_PASS;
        }
        return SK_PASS;
}


