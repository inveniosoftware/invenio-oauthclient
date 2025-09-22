Upgrading
=========

This page contains specific information on upgrading between certain versions of ``invenio-oauthclient`` where special steps are involved.

======
v6.0.0
======

This version involves an Alembic migration (``1758275763``) moving the ``extra_data`` column from the ``JSON`` type to the ``JSONB`` type (**only for PostgreSQL**).
By doing this, we can improve performance and use more advanced JSON queries.

For the majority of users, this shouldn't be an issue as the migration will be handled automatically when upgrading.
However, users with an ``oauthclient_remoteaccount`` table with ~50k+ rows should use an alternative approach, as this operation could overfill the WAL and affect the stability of the database, as well as creating a full lock for several minutes.

Instead, use these steps:

1. Install the new version of `invenio-oauthclient`, but do not run the Alembic migrations.

2. In an SQL console, run:

  .. code-block:: sql

    ALTER TABLE oauthclient_remoteaccount ADD COLUMN extra_data_b jsonb;

3. Next, run this query repeatedly until the response indicates that no new rows are being updated.
   You can control the batch size depending on your requirements using the ``LIMIT`` value.

  .. code-block:: sql

    WITH cte AS (
        SELECT id
        FROM oauthclient_remoteaccount
        WHERE extra_data_b IS NULL
        ORDER BY id
        LIMIT 1000
        FOR UPDATE SKIP LOCKED
    )
    UPDATE oauthclient_remoteaccount r
    SET extra_data_b = r.extra_data::jsonb
    FROM cte
    WHERE r.id = cte.id
    RETURNING r.id;

4. Double check there are no rows left to migrate.

  .. code-block:: sql

    SELECT COUNT(*) FROM oauthclient_remoteaccount WHERE extra_data_b IS NULL;

  This should return ``0``. If it does not, continue repeating step 3.

5. Drop and rename the columns in a simultaneous operation (this requires a brief lock but is much faster than the normal migration).

  .. code-block:: sql

    BEGIN;
    ALTER TABLE oauthclient_remoteaccount DROP COLUMN extra_data;
    ALTER TABLE oauthclient_remoteaccount RENAME COLUMN extra_data_b TO extra_data;
    COMMIT;

6. Finally, mark the relevant migration as having been manually performed.

  .. code-block:: bash

    invenio alembic stamp 1758275763
