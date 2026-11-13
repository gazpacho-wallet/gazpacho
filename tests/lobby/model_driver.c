/* Driver for the independent model (tests/lobby/lobby_model.py): reads one
 * case per line and answers with the engine's own functions. The model was
 * written from the specifications by someone who had not seen this code. */
#include "gazpacho/lobby.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    char line[4096];
    while (fgets(line, sizeof line, stdin)) {
        char *p = line + 1;
        unsigned long long v[64];
        int n = 0, used;
        while (n < 64 && sscanf(p, "%llu%n", &v[n], &used) == 1) { p += used; n++; }
        if (line[0] == 'S') {
            uint16_t mins[64];
            int chosen[64], k, i;
            for (i = 0; i < (int)v[2] && i < 61; i++) mins[i] = (uint16_t)v[3 + i];
            k = gz_lobby_choose((uint16_t)v[0], (uint16_t)v[1], mins, (int)v[2], chosen);
            if (k < 0) { printf("S none\n"); continue; }
            printf("S %d", k);
            for (i = 0; i < k; i++) printf(" %d", chosen[i]);
            printf("\n");
        } else if (line[0] == 'R') {
            static const char *name[3] = {"wait", "check", "cancel"};
            printf("R %s\n", name[gz_lobby_start_rule((uint16_t)v[0], (uint16_t)v[1], v[2], v[3], (uint32_t)v[4])]);
        } else if (line[0] == 'C') {
            static gz_lterms_outer_t o;
            gz_lterms_current_t c;
            gz_lobby_conditions_t cond;
            uint8_t term;
            int cls, k;
            static const char *name[4] = {"", "fits", "fits_now", "no"};
            memset(&o, 0, sizeof o);
            memset(&c, 0, sizeof c);
            memset(&cond, 0, sizeof cond);
            o.profile = (uint8_t)v[0]; o.lifetime_blocks = (uint32_t)v[1]; o.winddown_blocks = (uint32_t)v[2];
            o.channel_sat = v[3]; o.tree_feerate = (uint32_t)v[4];
            o.n_adj = c.n_adj = 3;
            for (k = 0; k < 3; k++) {
                o.adj[k].type = c.adj_type[k] = (uint8_t)(64 + 2 * k);
                o.adj[k].min = v[5 + 3 * k]; o.adj[k].max = v[6 + 3 * k]; c.adj_value[k] = v[7 + 3 * k];
            }
            cond.profiles = (uint8_t)v[14]; cond.life_min = (uint32_t)v[15]; cond.life_max = (uint32_t)v[16];
            cond.wind_max = (uint32_t)v[17]; cond.chan_min = v[18]; cond.rate_max = (uint32_t)v[19];
            cond.adj_max[0] = v[20]; cond.adj_max[1] = v[21]; cond.adj_max[2] = v[22];
            cond.current_only = (uint8_t)v[23];
            cls = gz_lterms_classify(&o, &c, &cond, &term);
            printf("C %s %d %d\n", name[cls], term, gz_lterms_ready_ok(cls, &cond));
        }
    }
    return 0;
}
