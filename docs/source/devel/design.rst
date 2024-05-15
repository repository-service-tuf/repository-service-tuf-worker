Worker design
#############

Context level
=============

The ``repository-service-tuf-worker``, in the context perspective, is a Consumer and
Publisher from the Broker that receives tasks to perform in the
`TUF Metadata Repository`. The `Metadata Repository` is stored using a
*Repository Storage Service* that reads/writes this data. For signing some of
the Metadata, the ``repository-service-tuf-worker`` uses the online key.

.. image:: /_static/repository-service-tuf-worker-C1.png


Container level
===============

The ``repository-service-tuf-worker``, in the container perspective, is a Metadata
Repository worker that performs actions to the TUF Metadata.

It will consume tasks from the Broker server and execute the task actions in
the Metadata Repository using the ``Storage Service`` to handle the TUF
Metadata. After executing any task, ``repository-service-tuf-api`` publishes to
the Broker.

The ``repository-service-tuf-worker`` implements the services ``Storage Service``.

Current supported Storage Services types:
    - LocalStorage (File System)
    - S3Storage (AWS S3 Object Storage -- to be implemented)

The ``repository-service-tuf-worker`` stores configuration settings. These are the
**Worker Settings**.

The ``repository-service-tuf-worker``also uses the **Repository Settings**, from
``RSTUF_REDIS_SERVER``.

**Worker Settings**: are related to the operational configurations to run the
``repository-service-tuf-worker`` such as worker id, Broker, type of Storage, Key
Vault services and their sub-configurations, etc.

**Repository Settings** are given by ``repository-service-tuf-api`` and
are stored in ``RSTUF_REDIS_SERVER`` to run routine tasks such as bumping
snapshot and timestamp metadata, etc.


.. image:: /_static/repository-service-tuf-worker-C2.png
