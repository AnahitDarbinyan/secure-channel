#include <stdio.h>
#include <stdlib.h>
#include "replay_window.h"

static int failures;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

int main(void)
{
    replay_window w;

    replay_window_init(&w);
    for (uint64_t i = 0; i < 100; i++)
        CHECK(replay_window_accept(&w, i) == 1);          /* in order      */
    CHECK(replay_window_accept(&w, 99) == 0);             /* duplicate     */
    CHECK(replay_window_accept(&w, 50) == 0);             /* duplicate     */
    CHECK(replay_window_accept(&w, 35) == 0);             /* too old (64+) */

    replay_window_init(&w);
    CHECK(replay_window_accept(&w, 10) == 1);
    CHECK(replay_window_accept(&w, 12) == 1);
    CHECK(replay_window_accept(&w, 11) == 1);             /* reordered ok  */
    CHECK(replay_window_accept(&w, 11) == 0);             /* but only once */
    CHECK(replay_window_accept(&w, 9)  == 1);             /* before first  */

    replay_window_init(&w);
    CHECK(replay_window_accept(&w, 0) == 1);
    CHECK(replay_window_accept(&w, 1000) == 1);           /* big jump      */
    CHECK(replay_window_accept(&w, 0) == 0);              /* now too old   */
    CHECK(replay_window_accept(&w, 1000 - 63) == 1);      /* edge of window*/
    CHECK(replay_window_accept(&w, 1000 - 64) == 0);      /* just outside  */

    if (failures) { printf("%d failure(s)\n", failures); return 1; }
    printf("replay window: all checks passed\n");
    return 0;
}
