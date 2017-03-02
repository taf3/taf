Contribution guidelines
=======================

Create an Issue
^^^^^^^^^^^^^^^
You can create an issue by the following link https://github.com/taf3/taf/issues if you:

* find a bug in a **TAF** project
* have trouble following the documentation
* have a question about the project

For more information on how issues work, check out GitHub `Issues guide <https://guides.github.com/features/issues/>`_ .

Code contribution
^^^^^^^^^^^^^^^^^
Pull Request
++++++++++++

You can create a pull request by the following link https://github.com/taf3/taf/pulls if you are able to:

* patch the bug
* add the new feature

Before you will do pull request you have to:

* understand the license
* sign a Contributor Licence Agreement (CLA) if required

.. note::

   All licenses and copyrights must be correct, and all code and information must have been pre-approved for public release.

GitHub workflow
+++++++++++++++

1. Dev makes github account
2. Dev forks taf to repo in personal github account  (e.g.  github.com/rbbratta/taf)
3. Dev uploads new patches to personal taf repo as topic branch
4. Dev makes pull request to taf3/taf for topic branch
5. Travis-ci runs unittests on pull request
6. We review pull request in weekly meeting, leave comments on GitHub
7. Merge to GitHub
8. Internal Jenkins polls GitHub and builds internal TAF Docker image for Berta
9. We test internally with GitHub taf3 Docker image

For more information on how to create pull request, check out GitHub https://help.github.com/categories/collaborating-with-issues-and-pull-requests/ .


