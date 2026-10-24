"""SQL tasks over a small shop schema loaded into a real Postgres schema per episode."""
from __future__ import annotations

import datetime as dt
import random
from dataclasses import dataclass

DDL = """
CREATE TABLE {s}.customers (id int PRIMARY KEY, name text NOT NULL, country text NOT NULL, signup_date date NOT NULL);
CREATE TABLE {s}.products (id int PRIMARY KEY, name text NOT NULL, category text NOT NULL, price numeric(8,2) NOT NULL);
CREATE TABLE {s}.orders (id int PRIMARY KEY, customer_id int NOT NULL REFERENCES {s}.customers(id),
                         order_date date NOT NULL, status text NOT NULL);
CREATE TABLE {s}.order_items (order_id int NOT NULL REFERENCES {s}.orders(id),
                              product_id int NOT NULL REFERENCES {s}.products(id),
                              qty int NOT NULL, PRIMARY KEY (order_id, product_id));
"""

FIRST = ["Ada", "Ben", "Cleo", "Dev", "Eli", "Fay", "Gus", "Hana", "Ivy", "Jon", "Kai", "Lea", "Max", "Nia", "Oz", "Pia"]
LAST = ["Stone", "Reyes", "Okafor", "Ito", "Novak", "Silva", "Khan", "Meyer", "Lund", "Rao"]
COUNTRIES = ["US", "DE", "IN", "JP", "BR"]
CATEGORIES = ["books", "games", "garden", "kitchen"]


def load_dataset(conn, schema: str, seed: int) -> None:
    """Create tables and deterministic data in `schema` (which must already exist)."""
    rng = random.Random(seed)
    conn.execute(DDL.format(s=schema))
    names = [f"{f} {l}" for f in FIRST for l in LAST]
    rng.shuffle(names)
    customers = [(i + 1, names[i], rng.choice(COUNTRIES), dt.date(2022, 1, 1) + dt.timedelta(days=rng.randint(0, 900)))
                 for i in range(40)]
    products = [(i + 1, f"{rng.choice(['Alpha', 'Bolt', 'Cedar', 'Dune', 'Ember', 'Flux'])}-{i + 1}",
                 CATEGORIES[i % 4], round(rng.uniform(3, 90), 2)) for i in range(24)]
    buyers = rng.sample([c[0] for c in customers], 32)
    orders, items = [], []
    for oid in range(1, 181):
        cid = rng.choice(buyers[:12]) if rng.random() < 0.4 else rng.choice(buyers)
        d = dt.date(2024, rng.randint(1, 12), rng.randint(1, 28))
        orders.append((oid, cid, d, rng.choices(["completed", "cancelled", "pending"], [0.78, 0.12, 0.10])[0]))
        for pid in rng.sample(range(1, 25), rng.randint(1, 4)):
            items.append((oid, pid, rng.randint(1, 5)))
    with conn.cursor() as cur:
        cur.executemany(f"INSERT INTO {schema}.customers VALUES (%s,%s,%s,%s)", customers)
        cur.executemany(f"INSERT INTO {schema}.products VALUES (%s,%s,%s,%s)", products)
        cur.executemany(f"INSERT INTO {schema}.orders VALUES (%s,%s,%s,%s)", orders)
        cur.executemany(f"INSERT INTO {schema}.order_items VALUES (%s,%s,%s)", items)


@dataclass(frozen=True)
class SqlTask:
    id: str
    prompt: str
    ref: str  # reference query; `{s}` is the schema placeholder
    ordered: bool


TASKS: dict[str, SqlTask] = {t.id: t for t in [
    SqlTask("revenue_top5",
            "Top 5 customers by revenue. Revenue = SUM(qty * price) over COMPLETED orders. "
            "Columns: name, revenue (rounded to 2 decimals). Order by revenue descending, then name.",
            "SELECT c.name, ROUND(SUM(oi.qty*p.price),2) AS revenue FROM {s}.customers c "
            "JOIN {s}.orders o ON o.customer_id=c.id AND o.status='completed' "
            "JOIN {s}.order_items oi ON oi.order_id=o.id JOIN {s}.products p ON p.id=oi.product_id "
            "GROUP BY c.name ORDER BY revenue DESC, c.name LIMIT 5", True),
    SqlTask("never_ordered",
            "Customers who have never placed an order of any status. Column: name. Order by name.",
            "SELECT c.name FROM {s}.customers c WHERE NOT EXISTS "
            "(SELECT 1 FROM {s}.orders o WHERE o.customer_id=c.id) ORDER BY c.name", True),
    SqlTask("monthly_completed",
            "Number of COMPLETED orders per month of 2024. Columns: month ('YYYY-MM'), orders. Order by month.",
            "SELECT to_char(order_date,'YYYY-MM') AS month, COUNT(*)::int AS orders FROM {s}.orders "
            "WHERE status='completed' GROUP BY 1 ORDER BY 1", True),
    SqlTask("category_best",
            "For each product category, the product with the most units sold in COMPLETED orders "
            "(ties: alphabetical by product name). Columns: category, product, units. Order by category.",
            "SELECT category, product, units FROM (SELECT p.category, p.name AS product, SUM(oi.qty)::int AS units, "
            "ROW_NUMBER() OVER (PARTITION BY p.category ORDER BY SUM(oi.qty) DESC, p.name) rn "
            "FROM {s}.products p JOIN {s}.order_items oi ON oi.product_id=p.id "
            "JOIN {s}.orders o ON o.id=oi.order_id AND o.status='completed' GROUP BY p.category, p.name) t "
            "WHERE rn=1 ORDER BY category", True),
    SqlTask("repeat_buyers",
            "Customers with at least 3 COMPLETED orders. Columns: name, n_orders. Order by n_orders descending, then name.",
            "SELECT c.name, COUNT(*)::int AS n_orders FROM {s}.customers c "
            "JOIN {s}.orders o ON o.customer_id=c.id AND o.status='completed' "
            "GROUP BY c.name HAVING COUNT(*)>=3 ORDER BY n_orders DESC, c.name", True),
]}

ORACLE_SEEDS = (880_001, 880_002, 880_003)
