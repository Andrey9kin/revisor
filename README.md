#Revisor#
Revisor is a strace-based audit tool intended to be used for build audit and version control agnostic build avoidance implementation.

Idea is to trace all files used for a build and then prepare a report that will consist of a list of files and checksums for them. Files generated during the build will be not included because we don't have interest in them.

###Features###
- Absolute paths extracted for all files included into the report
- Possibility to ignore patterns to exclude files from /app, /dev and other system directories

###License###
Revisor is just a fork of strace (http://sourceforge.net/projects/strace) and use the same license (BSD) as original project.