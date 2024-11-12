# zkGadgets

This repository contains a collection of "zero-knowledge gadgets" for the [ZoKrates][zokrates] language.

A gadget is a proof component that can be composed and re-used as part of a larger proof. It is small and efficient, using a few tricks to make expensive operations cheaper. Some gadgets require the prover and/or verifier to execute some code outside the proof, in native code, to check assumptions.

## Supported operations

The table below lists the operations we implemented.

We support all aggregation functions supported by the following platforms, except those that work on strings or JSON:

- Google: [Google Cloud Dataflow SQL's aggregate functions](https://cloud.google.com/dataflow/docs/reference/sql/aggregate_functions)
- Azure: [Microsoft Azure Stream Analytics](https://learn.microsoft.com/en-us/stream-analytics-query/aggregate-functions-azure-stream-analytics)
- Flink: [Apache Flink's aggregate functions](https://nightlies.apache.org/flink/flink-docs-release-1.18/docs/dev/table/functions/systemfunctions/#aggregate-functions) (used by Amazon Web Services)

| Operation | Type signature | Google | Azure | Flink | Complexity | Assumptions |
| --------- | -------------- | ------ | ----- | ----- | ---------- | ----------- |
| Count                             | `[]u64 -> u32`                  | ✅ | ✅ | ✅ | $O(1)$ | |
| Count distinct                    | `[]u64 -> u32`                  | ❌ | ✅ | ✅ | $O(n)$ | (2) |
| Collect distinct                  | `[]u64 -> []u64`                | ❌ | ❌ | ✅ | $O(n)$ | (2) |
| Sum                               | `[]u64 -> u64`                  | ✅ | ✅ | ✅ | $O(n)$ | (1) |
| Max, min                          | `[]u64 -> u64`                  | ✅ | ✅ | ✅ | $O(n)$ | (2) |
| Average                           | `[]u64 -> u64`                  | ✅ | ✅ | ✅ | $O(n)$ | (1) |
| Variance (population, sample)     | `[]u64 -> u64`                  | ❌ | ✅ | ✅ | $O(n)$ | (1) |
| Std dev (population, sample)      | `[]u64 -> u64`                  | ❌ | ✅ | ✅ | $O(n)$ | (1) (3) |
| Median                            | `[]u64 -> u64`                  | ❌ | ❌ | ❌ | $O(n)$ | (2) |
| Top N, bottom N                   | `[]u64 -> []u64`                | ❌ | ✅ | ❌ | $O(n)$ | (2) |
| Top distinct N, bottom distinct N | `[]u64 -> []u64`                | ❌ | ❌ | ❌ | $O(n)$ | (2) |
| Rank                              | `[]u64 -> u32`                  | ❌ | ❌ | ✅ | $O(n)$ | (2) |
| Dense rank                        | `[]u64 -> u32`                  | ❌ | ❌ | ✅ | $O(n)$ | (2) |
| Percent rank                      | `[]u64 -> u32`                  | ❌ | ❌ | ✅ | $O(n)$ | (2) |
| Cume dist                         | `[]u64 -> u32`                  | ❌ | ❌ | ✅ | $O(n)$ | (2) |
| Row number                        | `[]u64 -> u32`                  | ❌ | ❌ | ✅ | $O(n)$ | (2) |
| Ntile                             | `[]u64 -> u64`                  | ❌ | ❌ | ✅ | $O(n)$ | (2) |
| Percentile                        | `[]u64 -> u64`                  | ❌ | ✅ | ✅ | $O(n)$ | (2) |
| First, last                       | `[]u64 -> u64`                  | ❌ | ✅ | ✅ | $O(1)$ | |
| Lead, lag                         | `[]u64 -> u64`                  | ❌ | ❌/✅ | ✅ | $O(n)$ | (2) |
| Any, every                        | `[]bool -> bool`                | ❌ | ❌ | ❌ | $O(n)$ | |
| Bitwise AND, OR, XOR              | `[]bitmap -> bitmap`            | ❌ | ✅ | ❌ | $O(n)$ | |
| ~~List agg~~                      | `([]string, string) -> string`  | ❌ | ❌ | ✅ |
| ~~JSON object agg~~               | `[](string, T) -> JSON`         | ❌ | ❌ | ✅ |
| ~~JSON array agg~~                | `[]T -> JSON`                   | ❌ | ❌ | ✅ |

where `bitmap` = `[]bool`

Note that some operations do not work for empty lists. Median also does not work for a list of length 1.

Some operations require the prover to perform some computation before the proof. The assumptions are as follows:

- (1) Inputs must be small enough so that there are no overflows. E.g. to calculate average, the sum must fit in `u64`; to calculate variance & std dev, the sum of squares must fit in `u64`.
- (2) The prover must pre-sort the list. This is checked in the proof. The verifier must check if all elements were included!
- (3) The prover must provide the result of the square root as input. This is checked in the proof.

## Testing

To test the gadgets, run `./run.sh`.

## Tricks

The following tricks were used to make the gadgets more efficient:

- Lists have a static length `N` and an actual length `n` (`n` must be ≤ `N`). (Some operations return smaller lists, e.g. `distinct`. In those cases, the static length remains `N` and the actual length is updated.)
- Many operations assume the list is pre-sorted, to avoid sorting in proof. Hence, in the proof, we only have to check if the list is sorted. However, note that *the verifier must also check if all elements were included!*
- For some operations, we order arithmetic operations to maintain precision. E.g. in `variance`, the division is delayed until the end.
- For operations that rely on a square root (`stddev`), it must be pre-calculated. In the proof, we check whether it was calculated correctly. (Note also that, for $y = \sqrt{x}$, we only check if $y^2 \leq x < (y+1)^2$.)
- As there is no while loop, all loops have a static bound and a boolean that indicates whether updates should be made. (See e.g. `distinct`.)
- Some loops start at 1 (e.g. in `distincts`) as there is no short-circuiting and doing otherwise would trigger out-of-bounds errors.
- `median` for a list of length 1 does not work (otherwise the branch for an even number of elements triggers an out-of-bounds error, although this branch is not triggered).
- Functions that return percentiles, return values `* 100`. E.g. `percentile` returns the 90th percentile as `90` instead of `0.90`.

## License

This project is licensed under the BSD 3-Clause Clear License - see the [LICENSE](../LICENSE) file for details.

[zokrates]: https://zokrates.github.io/ "ZoKrates"
