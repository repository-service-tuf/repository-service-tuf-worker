###########
Development
###########


.. include:: design.rst



Component level
---------------
.. uml:: ../../diagrams/tuf-repository-service-worker-C3.puml


Component Specific
------------------

Adding/Removing targets
.......................

As mentioned at the container level, the domain of ``tuf-repository-service-worker``
(Repository Worker) is managing the TUF Repository Metadata.
The Repository Worker has an Metadata Repository (`MetadataRepository
<tuf_repository_service_worker.html#tuf_repository_service_worker.repository.MetadataRepository>`_) implementation
using `python-tuf <https://theupdateframework.readthedocs.io/en/latest/>`_.

The repository implementation has different methods such as adding new targets,
removing targets, bumping role metadata versions (ex: Snapshot and Timestamp),
etc.

The Repository Worker handles everything as a task.
To handle the tasks, the Repository Worker uses `Celery
<https://docs.celeryq.dev/en/stable/>`_ as Task Manager.

We have two types of tasks:

- First are tasks that Repository Work consumes from the Broker Server are
  tasks published by the `TUF Repository Service API
  <https://github.com/kaprien/tuf-repository-service-api>`_ in the ``repository_metadata``
  queue, sent by an API User.
- Second are tasks that Repository Work generates in the queue
  ``trs_internals``. Those are internal tasks for the Repository Worker
  maintenance.

The tasks are defined in the ``tuf-repository-service-worker/app.py```, and uses `Celery
Beat <https://docs.celeryq.dev/en/stable/userguide/periodic-tasks.html>`_ as
scheduler.

The repository Worker has two maintenance tasks:

- **Bump Roles** that contain online keys ("Snapshot", "Timestamp" and Hahsed
  Bins ("bins-XX").
- **Publish the new Hashed Bins Roles** ("bins-XX") with new/removed targets.

About **Bump Roles** (``bump_online_roles``) that contain online keys is easy.
These roles have short expiration (defined during repository configuration) and
must be "bumped" frequently. The implementation in the RepositoryMetadata

**Publish the new Hashed Bins Roles** (``publish_targets_meta``) is part of the
solution for the :ref:`Repository Worker scalability, Issue 17
<devel/known_issues:(Solved) Scalability>`.

To understand more, every time the API sends a task to add a new target, the
Hashed Bins Roles must be changed to add the new target(s), as the Snapshot and
Timestamp.

.. uml::

  @startuml
      !pragma useVerticalIf
      start
      :Add/Remove target(s);
      :1. Add the target(s) to the Hashed Bin Role;
      :2. Generate a new version;
      :2. Persist the new Hashed Bin Role in the Storage;
      :4. Update Hashed Bin Role version in the Snapshot meta;
      :5. Bump Snapshot version;
      :6. Persist the new Snapshot in the Storage;
      :7. Update Snapshot Version in the Timestamp;
      :8. Bump Timestamp Version;
      :9. Persist the new Timestamp in the Storage;
      stop
    @enduml

To give more flexibility to multiple Repository Workers to handle multiple
tasks and not wait until the entiry flow is done, per each task, we split it.

We use the 'waiting time' to alternate between tasks.

.. note::

   This is valid flow for the Repository Metadata Methods `add_targets
   <tuf_repository_service_worker.html#tuf_repository_service_worker.repository.MetadataRepository.add_targets>`_
   and `remove_targets
   <tuf_repository_service_worker.html#tuf_repository_service_worker.repository.MetadataRepository.remove_targets>`_

Before the Repository Worker adds/removes the new target and does steps 1 to 3,
it Locks [#f1]_ specific Hashed Bins Role, for example, bins-a.


It means the multiple Repository Workers can write multiple Hashed Bins Roles
simultaneously from various tasks.

When Step 3 finishes, the Repository Worker will lock  ``unpublished_meta`` and
add the Hashed Bins Role in the list if it does not exist.

.. uml::

  @startuml
      !pragma useVerticalIf
      start
      partition "add/remove targets" {
         :Group targets per Hashed Bins Role;
         repeat
         repeat while (Try Lock Hashed Bins Roles) is (Waiting)
            :Lock Hashed Bins;
            :Add the target(s) to the Hashed Bin Role;
            :Generate a new version;
            :Persist the new Hashed Bin Role in the Storage;
            repeat
            repeat while (Try Lock unpublished_meta) is (Waiting)
            :Lock unpublished_meta;
            if (Hashed Bins Role in umpublished_meta) then (not in)
               :Add Hashed Bins name;
            endif
            :Unlock unpublished_meta;
            :Unlock Hashed Bins Roles;
         repeat
         repeat while (all Hashed Bins are Published) is (Waiting)
         stop
      }
   @enduml

Every minute, the routine task **Publish the new Hashed Bins Roles** runs and
gets the names of the unpublished Hashed Bins Roles, looks in the Storage the
latest version and runs steps 4 to 9, and flushes the ``unpublished_meta``.

.. uml::

   @startuml
      partition "publish targets meta" {
         start
         if (unpublished_meta is empty) then (True)
            stop
         else
            repeat
            repeat while (Try LOCK unpublished_meta) is (Waiting)
            :Update Hashed Bin Role version in the Snapshot meta;
            :Bump Snapshot version;
            :Persist the new Snapshot in the Storage;
            :Update Snapshot Version in the Timestamp;
            :Bump Timestamp Version;
            :Persist the new Timestamp in the Storage;
            :Flush unpublished_meta;
            :UNLOCK unpublished_meta;
            stop
         endif
      }
    @enduml


.. [#f1]

   Lock is used Celery task. `It is used to ensure a task is only executed one
   at a time <https://docs.celeryq.dev/en/stable/tutorials/task-cookbook.html
   ?highlight=Task%20cookbook#ensuring-a-task-is-only-executed-one-at-a-time>`_
   . I avoid that two tasks write the same metadata, causing a race condition.

Important issues/problems
.........................

.. toctree::
   :maxdepth: 1

   known_issues

Implementation
..............

.. toctree::
   :maxdepth: 3

   tuf_repository_service_worker
   tuf_repository_service_worker.services
   tuf_repository_service_worker.services.storage
   tuf_repository_service_worker.services.keyvault
   modules