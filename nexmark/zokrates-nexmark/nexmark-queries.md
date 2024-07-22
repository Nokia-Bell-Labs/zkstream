# Nexmark queries

There are three tables:

- `person` contains information about the users (sellers and bidders):
  - id
  - name
  - emailAddress
  - creditCard
  - city
  - state
  - dateTime: creation time
  - extra
- `auction` contains the auctions:
  - id
  - itemName
  - description
  - initialBid
  - reserve: price to 'reserve' the auction
  - dateTime: start time
  - expires: end time
  - seller: id
  - category: category id
  - extra
- `bid` contains the bids:
  - auction: id
  - bidder: id
  - price
  - dateTime
  - extra

We assume the system is initialized with the persons and auctions.
Then, bids are messages sent into the system, where the `auction` and `price`
must be kept confidential. The `bidder` is the sender of the message.

For our set-up, we generated:

- 5 persons, in 4 states.
- 25 auctions, in 5 categories.
- 500 bids.

This corresponds to an average of 20 bids per auction and 5 auctions per category.

Note: quoted descriptions (>) below are from the original paper. The SQL is
either from the paper or from [nexmark-flink][nexmark-flink], depending on which
is more readable for our purposes.

[nexmark-flink]: https://github.com/nexmark/nexmark/blob/master/nexmark-flink/src/main/resources/queries/

## Query 1: Currency Conversion

> Query 1 takes an incoming bid stream and converts the prices of the bids from
> U.S. dollars to Euros.

In the original paper, the query is:

```sql
SELECT
    auction,
    bidder,
    0.908 * price as price, -- convert dollar to euro
    dateTime,
    extra
FROM bid;
```

Although this query is leaking confidential data, we include it as it is useful
to show the overhead on a simple query that processes one message.

## Query 2: Selection

> Query 2 selects all bids on a set of five items.

In the original paper, the query is:

```sql
SELECT itemid, price
FROM bid
WHERE itemid = 1007 OR
    itemid = 1020 OR
    itemid = 2001 OR
    itemid = 2019 OR
    itemid = 1087;
```

We do not include this query as it leaks confidential data.

## Query 3: Local Item Suggestion

> [Query 3 outputs] a result every time a new item becomes for sale in category
> 10 in Oregon.

Nexmark-flink extends this to three states:

```sql
SELECT
    P.name, P.city, P.state, A.id
FROM
    auction AS A INNER JOIN person AS P on A.seller = P.id
WHERE
    A.category = 10 and (P.state = 'OR' OR P.state = 'ID' OR P.state = 'CA');
```

We do not include this query as it only uses public data, hence it does not
require a ZKP.

## Query 4: Average Price for a Category

> Query 4 joins the [categories] with the [closed] auction stream to calculate
> average [closing] price for each.

In nexmark-flink, the query is:

```sql
SELECT Q.category, AVG(Q.final)
FROM (
    SELECT MAX(B.price) AS final, A.category
    FROM auction A, bid B
    WHERE A.id = B.auction AND B.dateTime BETWEEN A.dateTime AND A.expires
    GROUP BY A.id, A.category
) Q
GROUP BY Q.category;
```

This query is executed in two steps:

1. Group the bids per auction, and select the maximum bid.
2. Group the (highest bid per auction) per category and calculate the average.

Note that checking that all bids are on auctions of the same category must be
done outside the proof.

## Query 5: Hot Items

> [Query 5] selects the item [= auction] with the most bids in the past one hour
> time period; the “hottest” item.

In the original paper, the query is:

```sql
SELECT bid.itemid
FROM bid [RANGE 60 MINUTES PRECEDING]
WHERE (SELECT COUNT(bid.itemid)
    FROM bid [PARTITION BY bid.itemid RANGE 60 MINUTES PRECEDING])
    >= ALL (SELECT COUNT(bid.itemid)
        FROM bid [PARTITION BY bid.itemid RANGE 60 MINUTES PRECEDING]);
```

This query is executed in two steps:

1. Group the bids per auction, and count the number of bids.
2. Select the maximum value.

## Query 6: Average Selling Price by Seller

> Query 6 calculates, for each seller, the average selling price of items sold
> by that seller.

In nexmark-flink, the query is:

```sql
SELECT
    Q.seller,
    AVG(Q.price) OVER
        (PARTITION BY Q.seller ORDER BY Q.dateTime ROWS BETWEEN 10 PRECEDING AND CURRENT ROW)
FROM (
    SELECT *, ROW_NUMBER() OVER (PARTITION BY A.id, A.seller ORDER BY B.price DESC) AS rownum
    FROM (SELECT A.id, A.seller, B.price, B.dateTime
        FROM auction AS A,
            bid AS B
        WHERE A.id = B.auction
            and B.dateTime between A.dateTime and A.expires)
    WHERE rownum <= 1
) AS Q;
```

Note: this query is actually not yet supported in Flink SQL.

This query is executed in two steps:

1. Group the bids per auction and seller, and select the maximum bid.
2. Group the (highest bid per auction) per seller and calculate the average.

Note that checking that all bids are on auctions of the same seller must be
done outside the proof.

## Query 7: Highest Bid

> Query 7 monitors the highest price items currently on auction.

In the original paper, the query is:

```sql
SELECT bid.price, bid.itemid
FROM bid where bid.price =
    (SELECT MAX(bid.price)
    FROM bid [FIXEDRANGE 10 MINUTES PRECEDING]);
```

This query simply selects the highest bid.

## Query 8: Monitor New Users

> [Query 8] finds people who put something up for sale within twelve hours of
> registering to use the auction service.

```sql
SELECT person.id, person.name
FROM person [RANGE 12 HOURS PRECEDING], auction [RANGE 12 HOURS PRECEDING]
WHERE person.id = auction.sellerId;
```

We do not include this query as it only uses public data.
