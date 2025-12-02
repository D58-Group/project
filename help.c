/* ===================== Time-series stats ===================== */

#define TS_WINDOW_SEC 1.0   /* duration of each time bin in seconds */

typedef struct ts_bin {
    double   start_time;   /* start of window in relative seconds */
    uint64_t pkt_count;    /* packets in this window */
    uint64_t byte_count;   /* bytes in this window */

    uint64_t tcp_count;    /* per-protocol counters */
    uint64_t udp_count;
    uint64_t icmp_count;
    uint64_t other_count;

    struct ts_bin *next;
} ts_bin_t;

static ts_bin_t *ts_head = NULL;
static ts_bin_t *ts_tail = NULL;
static pthread_mutex_t ts_lock = PTHREAD_MUTEX_INITIALIZER;

//make new bins 
static ts_bin_t *ts_ensure_bin_for_time(double t_rel) {
    if (!ts_head) {
        ts_bin_t *bin = calloc(1, sizeof(ts_bin_t));
        if (!bin) return NULL;
        bin->start_time = floor(t_rel / TS_WINDOW_SEC) * TS_WINDOW_SEC;
        ts_head = ts_tail = bin;
        return bin;
    }

    while (t_rel >= ts_tail->start_time + TS_WINDOW_SEC) {
        ts_bin_t *bin = calloc(1, sizeof(ts_bin_t));
        if (!bin) return ts_tail; 
        bin->start_time = ts_tail->start_time + TS_WINDOW_SEC;
        ts_tail->next = bin;
        ts_tail = bin;
    }

    return ts_tail;
}

/* Extract L3 protocol number if IPv4, else 0. */
static uint8_t ts_get_proto(const uint8_t *packet, uint32_t caplen) {
    if (caplen < sizeof(sr_ethernet_hdr_t)) return 0;

    uint16_t ethtype_val = ethertype((uint8_t *)packet);
    if (ethtype_val != ethertype_ip) return 0;

    if (caplen < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) return 0;

    const sr_ip_hdr_t *ip =
        (const sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    return ip->ip_p;  /* TCP=6, UDP=17, ICMP=1, etc. */
}

/* Update stats for a single packet at time t_rel. Call from handle_packet. */
static void ts_update(double t_rel,
                      const uint8_t *packet,
                      const struct pcap_pkthdr *hdr)
{
    pthread_mutex_lock(&ts_lock);

    ts_bin_t *bin = ts_ensure_bin_for_time(t_rel);
    if (!bin) {
        pthread_mutex_unlock(&ts_lock);
        return;
    }

    bin->pkt_count++;
    bin->byte_count += hdr->len;

    uint8_t proto = ts_get_proto(packet, hdr->len);
    switch (proto) {
        case 6:  bin->tcp_count++;  break;  /* TCP */
        case 17: bin->udp_count++;  break;  /* UDP */
        case 1:  bin->icmp_count++; break;  /* ICMP */
        default: bin->other_count++; break;
    }

    pthread_mutex_unlock(&ts_lock);
}

/* Optional helper to print last n bins. */
static void ts_print_last_bins(int n) {
    pthread_mutex_lock(&ts_lock);

    int total = 0;
    ts_bin_t *cur = ts_head;
    while (cur) {
        total++;
        cur = cur->next;
    }

    int skip = (total > n) ? (total - n) : 0;

    cur = ts_head;
    for (int i = 0; i < skip && cur; i++) {
        cur = cur->next;
    }

    printf("\n=== Time-series stats (last %d bins, %.1fs each) ===\n",
           n, TS_WINDOW_SEC);

    while (cur) {
        double end = cur->start_time + TS_WINDOW_SEC;
        printf("[%.3f, %.3f): pkts=%llu bytes=%llu  TCP=%llu UDP=%llu ICMP=%llu OTHER=%llu\n",
               cur->start_time,
               end,
               (unsigned long long)cur->pkt_count,
               (unsigned long long)cur->byte_count,
               (unsigned long long)cur->tcp_count,
               (unsigned long long)cur->udp_count,
               (unsigned long long)cur->icmp_count,
               (unsigned long long)cur->other_count);
        cur = cur->next;
    }

    printf("===============================================\n");
    pthread_mutex_unlock(&ts_lock);
}
