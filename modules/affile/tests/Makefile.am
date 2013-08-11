modules_affile_tests_TESTS				= \
	modules/affile/tests/test_affile_open_file

check_PROGRAMS						+= \
	${modules_affile_tests_TESTS}

modules_affile_tests_test_affile_open_file_CFLAGS 	= $(TEST_CFLAGS)
modules_affile_tests_test_affile_open_file_LDADD	= $(TEST_LDADD) \
	-dlpreopen $(top_builddir)/modules/affile/libaffile.la
modules_affile_tests_test_affile_open_file_LDFLAGS 	=   \
	$(PREOPEN_CORE)
		
modules_affile_tests_TESTS			=	\
	modules/affile/tests/test_filemonitor

check_PROGRAMS					+=	\
	${modules_affile_tests_TESTS}

modules_affile_tests_test_filemonitor_CFLAGS	=	\
	$(TEST_CFLAGS)					\
	-I$(top_srcdir)/modules/affile
modules_affile_tests_test_filemonitor_LDADD	=	\
	$(TEST_LDADD)					\
	$(top_builddir)/modules/affile/filemonitor.lo
modules_affile_tests_test_filemonitor_LDFLAGS	=	\
	$(PREOPEN_CORE)
