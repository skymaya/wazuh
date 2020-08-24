/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include "../../headers/shared.h"
#include "../../analysisd/logtest.h"

int w_logtest_init_parameters();
void *w_logtest_init();
void w_logtest_remove_session(char *token);
void *w_logtest_check_inactive_sessions(__attribute__((unused)) void * arg);
int w_logtest_fts_init(OSList **fts_list, OSHash **fts_store);
w_logtest_session_t *w_logtest_initialize_session(char *token, OSList* list_msg);
char * w_logtest_generate_token();
int w_logtest_get_rule_level(cJSON * json_log_processed);
w_logtest_session_t * w_logtest_get_session(cJSON * req, OSList * list_msg);
void w_logtest_add_msg_response(cJSON * response, OSList * list_msg, int * error_code);
bool w_logtest_check_input(char * input_json, cJSON ** req, OSList * list_msg);
char * w_logtest_process_request(char * raw_request);

int logtest_enabled = 1;

int random_bytes_result = 0;

char * cJSON_error_ptr = NULL;

/* setup/teardown */



/* wraps */

int __wrap_OS_BindUnixDomain(const char *path, int type, int max_msg_size) {
    return mock();
}

int __wrap_accept(int __fd, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len) {
    return mock();
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__os_analysisd_add_logmsg(OSList * list, int level, int line, const char * func,
                                    const char * file, char * msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(level);
    check_expected_ptr(list);
    check_expected(formatted_msg);
}

int __wrap_pthread_mutex_init() {
    return mock();
}

int __wrap_pthread_mutex_lock() {
    return mock();
}

int __wrap_pthread_mutex_unlock() {
    return mock();
}

int __wrap_pthread_mutex_destroy() {
    return mock();
}

int __wrap_ReadConfig(int modules, const char *cfgfile, void *d1, void *d2) {
    if (!logtest_enabled) {
        w_logtest_conf.enabled = false;
    }
    return mock();
}

OSHash *__wrap_OSHash_Create() {
    return mock_type(OSHash *);
}

int __wrap_OSHash_setSize(OSHash *self, unsigned int new_size) {
    if (new_size) check_expected(new_size);
    return mock();
}

OSList *__wrap_OSList_Create() {
    return mock_type(OSList *);
}

OSListNode *__wrap_OSList_GetFirstNode(OSList * list) {
    return mock_type(OSListNode *);
}

int __wrap_OSList_SetMaxSize() {
    return mock();
}

void __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap_w_mutex_init() {
    return;
}

void __wrap_w_mutex_destroy() {
    return;
}

void __wrap_w_create_thread() {
    return;
}

int __wrap_close (int __fd) {
    return mock();
}

int __wrap_getDefine_Int() {
    return mock();
}

void * __wrap_OSHash_Delete_ex(OSHash *self, const char *key) {
    if (key) check_expected(key);
    return mock_type(void *);
}

int __wrap_OSHash_Add_ex(OSHash *hash, const char *key, void *data) {
    if (key) check_expected(key);
    if (data) check_expected(data);
    return mock_type(int);
}

void * __wrap_OSHash_Get_ex(OSHash *self, const char *key) {
    if (key) check_expected(key);
    return mock_type(void *);
}

void __wrap_os_remove_rules_list(RuleNode *node) {
    return;
}

void * __wrap_OSHash_Free(OSHash *self) {
    return mock_type(void *);
}

void __wrap_os_remove_decoders_list(OSDecoderNode *decoderlist_pn, OSDecoderNode *decoderlist_npn) {
    return;
}

void __wrap_os_remove_cdblist(ListNode **l_node) {
    return;
}

void __wrap_os_remove_cdbrules(ListRule **l_rule) {
    os_free(*l_rule);
    return;
}

void __wrap_os_remove_eventlist(EventList *list) {
    os_free(list);
    return;
}

unsigned int __wrap_sleep (unsigned int __seconds) {
    return mock_type(unsigned int);
}

OSHashNode *__wrap_OSHash_Begin(const OSHash *self, unsigned int *i) {
    return mock_type(OSHashNode *);
}

time_t __wrap_time(time_t *t) {
    return mock_type(time_t);
}

double __wrap_difftime (time_t __time1, time_t __time0) {
    return mock();
}

OSHashNode *__wrap_OSHash_Next(const OSHash *self, unsigned int *i, OSHashNode *current) {
    return mock_type(OSHashNode *);
}

OSStore *__wrap_OSStore_Free(OSStore *list) {
    return mock_type(OSStore *);
}

void __wrap_OS_CreateEventList(int maxsize, EventList *list) {
    return;
}

int __wrap_ReadDecodeXML(const char *file, OSDecoderNode **decoderlist_pn,
                        OSDecoderNode **decoderlist_nopn, OSStore **decoder_list,
                        OSList* log_msg) {
    return mock_type(int);
}

int __wrap_SetDecodeXML(OSList* log_msg, OSStore **decoder_list,
                        OSDecoderNode **decoderlist_npn, OSDecoderNode **decoderlist_pn) {
    return mock_type(int);
}

int __wrap_Lists_OP_LoadList(char * files, ListNode ** cdblistnode) {
    return mock_type(int);
}

void __wrap_Lists_OP_MakeAll(int force, int show_message, ListNode **lnode) {
    return;
}

int __wrap_Rules_OP_ReadRules(char * file, RuleNode ** rule_list, ListNode ** cbd , EventList ** evet , OSList * msg) {
    return mock_type(int);
}

void __wrap_OS_ListLoadRules(ListNode **l_node, ListRule **lrule) {
    return;
}

int __wrap__setlevels(RuleNode *node, int nnode) {
    return mock_type(int);
}

int __wrap_AddHash_Rule(RuleNode *node) {
    return mock_type(int);
}

int __wrap_Accumulate_Init(OSHash **acm_store, int *acm_lookups, time_t *acm_purge_ts) {
    return mock_type(int);
}

void __wrap_randombytes(void * ptr, size_t length) {
    check_expected(length);
    *((int32_t *) ptr) = random_bytes_result;
    return;
}

cJSON * __wrap_cJSON_ParseWithOpts(const char *value, const char **return_parse_end,
                                   cJSON_bool require_null_terminated) {
    *return_parse_end = cJSON_error_ptr;
    return mock_type(cJSON *);
}

cJSON * __wrap_cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string) {
    return mock_type(cJSON *);
}

cJSON_bool __wrap_cJSON_IsNumber(const cJSON * const item) {
    return mock_type(cJSON_bool);
}

cJSON * __wrap_cJSON_CreateArray() {
    return mock_type(cJSON *);
}

cJSON * __wrap_cJSON_CreateObject() { 
    return mock_type(cJSON *); 
}

cJSON * __wrap_cJSON_AddNumberToObject(cJSON * const object, const char * const name, const double number) {
    check_expected(number);
    check_expected(name);
    return mock_type(cJSON *);
}

char * __wrap_cJSON_PrintUnformatted(const cJSON *item){
    return mock_type(char *);
}

void __wrap_cJSON_Delete(cJSON *item){
    return;
}

cJSON_bool __wrap_cJSON_IsString(const cJSON * const item) {
    return mock_type(cJSON_bool);
}

void __wrap_cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string){
    return;
}

void __wrap_cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item){
    check_expected(object);
    check_expected(string);
    return;
}

cJSON * __wrap_cJSON_CreateString(const char *string){
    return mock_type(cJSON *);
}

void __wrap_cJSON_AddItemToArray(cJSON *array, cJSON *item) {
    return;
}

void __wrap_os_analysisd_free_log_msg(os_analysisd_log_msg_t ** log_msg) {
    os_free((*log_msg)->file);
    os_free((*log_msg)->func);
    os_free((*log_msg)->msg);
    os_free(*log_msg);
    return;
}

char * __wrap_os_analysisd_string_log_msg(os_analysisd_log_msg_t * log_msg) {
    return mock_type(char *);
}

void __wrap_OSList_DeleteCurrentlyNode(OSList *list) {
    if (list) {
        os_free(list->cur_node)
    }
    return;
}

int __wrap_wm_strcat(char **str1, const char *str2, char sep) {
    if(*str1 == NULL){
        os_calloc(4 , sizeof(char), *str1);
    }
    check_expected(str2);
    return mock_type(int);
}

/* tests */

/* w_logtest_init_parameters */
void test_w_logtest_init_parameters_invalid(void **state)
{
    will_return(__wrap_ReadConfig, OS_INVALID);

    int ret = w_logtest_init_parameters();
    assert_int_equal(ret, OS_INVALID);

}

void test_w_logtest_init_parameters_done(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    int ret = w_logtest_init_parameters();
    assert_int_equal(ret, OS_SUCCESS);

}

/* w_logtest_init */
void test_w_logtest_init_error_parameters(void **state)
{
    will_return(__wrap_ReadConfig, OS_INVALID);

    expect_string(__wrap__merror, formatted_msg, "(7304): Invalid wazuh-logtest configuration");

    w_logtest_init();

}


void test_w_logtest_init_logtest_disabled(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    logtest_enabled = 0;

    expect_string(__wrap__minfo, formatted_msg, "(7201): Logtest disabled");

    w_logtest_init();

    logtest_enabled = 1;

}

void test_w_logtest_init_conection_fail(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    will_return(__wrap_OS_BindUnixDomain, OS_SOCKTERR);

    expect_string(__wrap__merror, formatted_msg, "(7300): Unable to bind to socket '/queue/ossec/logtest'. Errno: (0) Success");

    w_logtest_init();

}

void test_w_logtest_init_OSHash_create_fail(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    will_return(__wrap_OS_BindUnixDomain, OS_SUCCESS);

    will_return(__wrap_OSHash_Create, NULL);

    expect_string(__wrap__merror, formatted_msg, "(7303): Failure to initialize all_sesssions hash");

    w_logtest_init();

}

void test_w_logtest_init_OSHash_setSize_fail(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    will_return(__wrap_OS_BindUnixDomain, OS_SUCCESS);

    will_return(__wrap_OSHash_Create, 1);

    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, NULL);

    expect_string(__wrap__merror, formatted_msg, "(7305): Failure to resize all_sesssions hash");

    w_logtest_init();

}

void test_w_logtest_init_done(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    will_return(__wrap_OS_BindUnixDomain, OS_SUCCESS);

    will_return(__wrap_OSHash_Create, 1);

    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);

    expect_string(__wrap__minfo, formatted_msg, "(7200): Logtest started");

    // Needs to implement w_logtest_main

    w_logtest_init();

}

/* w_logtest_fts_init */
void test_w_logtest_fts_init_create_list_failure(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1290): Unable to create a new list (calloc).");

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 0);

}

void test_w_logtest_fts_init_SetMaxSize_failure(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;
    OSList *list = (OSList *) 1;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, list);

    will_return(__wrap_OSList_SetMaxSize, 0);

    expect_string(__wrap__merror, formatted_msg, "(1292): Error setting error size.");

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 0);

}

void test_w_logtest_fts_init_create_hash_failure(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;
    OSList *list = (OSList *) 1;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, list);

    will_return(__wrap_OSList_SetMaxSize, 1);

    will_return(__wrap_OSHash_Create, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1295): Unable to create a new hash (calloc).");

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 0);

}

void test_w_logtest_fts_init_setSize_failure(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;
    OSList *list = (OSList *) 1;
    OSHash *hash = (OSHash *) 1;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, list);

    will_return(__wrap_OSList_SetMaxSize, 1);

    will_return(__wrap_OSHash_Create, hash);

    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 0);

    expect_string(__wrap__merror, formatted_msg, "(1292): Error setting error size.");

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 0);

}

void test_w_logtest_fts_init_success(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;
    OSList *list = (OSList *) 1;
    OSHash *hash = (OSHash *) 1;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, list);

    will_return(__wrap_OSList_SetMaxSize, 1);

    will_return(__wrap_OSHash_Create, hash);

    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 1);

}

/* w_logtest_remove_session */
void test_w_logtest_remove_session_fail(void **state)
{
    char * key = "test";

    expect_value(__wrap_OSHash_Delete_ex, key, "test");
    will_return(__wrap_OSHash_Delete_ex, NULL);

    w_logtest_remove_session(key);

}

void test_w_logtest_remove_session_OK(void **state)
{

    char * key = "test";
    w_logtest_session_t *session;
    os_calloc(1, sizeof(w_logtest_session_t), session);

    expect_value(__wrap_OSHash_Delete_ex, key, "test");
    will_return(__wrap_OSHash_Delete_ex, session);

    will_return(__wrap_OSStore_Free, session->decoder_store);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_OSHash_Free, session);

    w_logtest_remove_session(key);

}

/* w_logtest_check_inactive_sessions */
void test_w_logtest_check_inactive_sessions_no_remove(void **state)
{
    w_logtest_session_t *session;
    os_calloc(1, sizeof(w_logtest_session_t), session);
    session->last_connection = 1;

    OSHashNode *hash_node;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    hash_node->key = "test";
    hash_node->data = session;

    will_return(__wrap_FOREVER, 1);

    will_return(__wrap_sleep, 0);

    will_return(__wrap_OSHash_Begin, hash_node);

    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_time, NULL);

    will_return(__wrap_difftime, 1);

    will_return(__wrap_pthread_mutex_unlock, 0);

    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_FOREVER, 0);

    w_logtest_check_inactive_sessions(NULL);

    os_free(session);
    os_free(hash_node);

}

void test_w_logtest_check_inactive_sessions_remove(void **state)
{
    w_logtest_session_t *session;
    os_calloc(1, sizeof(w_logtest_session_t), session);
    session->last_connection = 1;

    OSHashNode *hash_node;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    hash_node->key = "test";
    hash_node->data = session;

    will_return(__wrap_FOREVER, 1);

    will_return(__wrap_sleep, 0);

    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_OSHash_Begin, hash_node);

    will_return(__wrap_time, NULL);

    will_return(__wrap_difftime, 1000000);

    will_return(__wrap_pthread_mutex_unlock, 0);

    // test_w_logtest_remove_session_ok
    char * key = "test";

    expect_value(__wrap_OSHash_Delete_ex, key, "test");
    will_return(__wrap_OSHash_Delete_ex, session);

    will_return(__wrap_OSStore_Free, NULL);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_OSHash_Free, session);


    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_FOREVER, 0);

    w_logtest_check_inactive_sessions(NULL);

    os_free(hash_node);

}

/* w_logtest_initialize_session */
void test_w_logtest_initialize_session_error_decoders(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 1;
    w_logtest_session_t * session;

    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_ReadDecodeXML, 0);

    // test_w_logtest_remove_session_ok_error_load_decoder_cbd_rules_hash
    will_return(__wrap_OSStore_Free, (OSStore *) 1);

    session = w_logtest_initialize_session(token, msg);

    assert_null(session);

    os_free(Config.decoders);
}

void test_w_logtest_initialize_session_error_cbd_list(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 1;
    w_logtest_session_t * session;

    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    char * cbd_file = "test.xml";
    Config.lists = calloc(2, sizeof(char *));
    Config.lists[0] = cbd_file;

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 0);
    will_return(__wrap_Lists_OP_LoadList, -1);

    // test_w_logtest_remove_session_ok_error_load_decoder_cbd_rules_hash
    will_return(__wrap_OSStore_Free, (OSStore *) 1);

    session = w_logtest_initialize_session(token, msg);

    assert_null(session);

    os_free(Config.decoders);
    os_free(Config.lists);
}

void test_w_logtest_initialize_session_error_rules(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 1;
    w_logtest_session_t * session;

    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    char * cbd_file = "test.xml";
    Config.lists = calloc(2, sizeof(char *));
    Config.lists[0] = cbd_file;

    char * include_file = "test.xml";
    Config.includes = calloc(2, sizeof(char *));
    Config.includes[0] = include_file;

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 0);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, -1);

    // test_w_logtest_remove_session_ok_error_load_decoder_cbd_rules_hash
    will_return(__wrap_OSStore_Free, (OSStore *) 1);

    session = w_logtest_initialize_session(token, msg);

    assert_null(session);

    os_free(Config.includes);
    os_free(Config.decoders);
    os_free(Config.lists);
}

void test_w_logtest_initialize_session_error_hash_rules(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 1;
    w_logtest_session_t * session;

    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    char * cbd_file = "test.xml";
    Config.lists = calloc(2, sizeof(char *));
    Config.lists[0] = cbd_file;

    char * include_file = "test.xml";
    Config.includes = calloc(2, sizeof(char *));
    Config.includes[0] = include_file;

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 0);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 0);

    // test_w_logtest_remove_session_ok_error_load_decoder_cbd_rules_hash
    will_return(__wrap_OSStore_Free, (OSStore *) 1);

    session = w_logtest_initialize_session(token, msg);

    assert_null(session);

    os_free(Config.includes);
    os_free(Config.decoders);
    os_free(Config.lists);
}

void test_w_logtest_initialize_session_error_fts_init(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 1;
    w_logtest_session_t * session;

    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    char * cbd_file = "test.xml";
    Config.lists = calloc(2, sizeof(char *));
    Config.lists[0] = cbd_file;

    char * include_file = "test.xml";
    Config.includes = calloc(2, sizeof(char *));
    Config.includes[0] = include_file;

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 0);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 1);
    will_return(__wrap_AddHash_Rule, 0);

    /* FTS init fail */
    OSList * fts_list;
    OSHash * fts_store;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, NULL);
    expect_string(__wrap__merror, formatted_msg, "(1290): Unable to create a new list (calloc).");

    // test_w_logtest_remove_session_ok_error_FTS_INIT
    will_return(__wrap_OSStore_Free, (OSStore *) 1);
    will_return(__wrap_OSHash_Free, (OSHash *) 0);

    session = w_logtest_initialize_session(token, msg);

    assert_null(session);

    os_free(Config.includes);
    os_free(Config.decoders);
    os_free(Config.lists);
}

void test_w_logtest_initialize_session_error_accumulate_init(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 1;
    w_logtest_session_t * session;

    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    char * cbd_file = "test.xml";
    Config.lists = calloc(2, sizeof(char *));
    Config.lists[0] = cbd_file;

    char * include_file = "test.xml";
    Config.includes = calloc(2, sizeof(char *));
    Config.includes[0] = include_file;

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 0);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 1);
    will_return(__wrap_AddHash_Rule, 0);

    /* FTS init success */
    OSList * fts_list;
    OSHash * fts_store;
    OSList * list;
    os_calloc(1, sizeof(OSList), list);
    OSHash * hash = (OSHash *) 1;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, list);
    will_return(__wrap_OSList_SetMaxSize, 1);
    will_return(__wrap_OSHash_Create, hash);
    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);

    will_return(__wrap_Accumulate_Init, 0);

    // test_w_logtest_remove_session_ok_error_acm
    will_return(__wrap_OSStore_Free, (OSStore *) 1);
    will_return(__wrap_OSHash_Free, (OSStore *) 1);
    will_return(__wrap_OSHash_Free, (OSStore *) 1);

    session = w_logtest_initialize_session(token, msg);

    assert_null(session);

    os_free(Config.includes);
    os_free(Config.decoders);
    os_free(Config.lists);
}

void test_w_logtest_initialize_session_success(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 1;
    w_logtest_session_t * session;

    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    char * cbd_file = "test.xml";
    Config.lists = calloc(2, sizeof(char *));
    Config.lists[0] = cbd_file;

    char * include_file = "test.xml";
    Config.includes = calloc(2, sizeof(char *));
    Config.includes[0] = include_file;

    will_return(__wrap_time, 1212);
    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 0);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 1);
    will_return(__wrap_AddHash_Rule, 0);

    /* FTS init success */
    OSList * fts_list;
    OSHash * fts_store;
    OSList * list = (OSList *) 1;
    OSHash * hash = (OSHash *) 1;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, list);
    will_return(__wrap_OSList_SetMaxSize, 1);
    will_return(__wrap_OSHash_Create, hash);
    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);

    will_return(__wrap_Accumulate_Init, 1);

    session = w_logtest_initialize_session(token, msg);

    assert_non_null(session);
    assert_false(session->expired);
    assert_int_equal(session->last_connection, 1212);

    os_free(token);
    os_free(session->eventlist);
    os_free(session);
    os_free(Config.includes);
    os_free(Config.decoders);
    os_free(Config.lists);
}

/* w_logtest_generate_token */
void test_w_logtest_generate_token_success(void ** state) {

    char * token = NULL;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    token = w_logtest_generate_token();

    assert_non_null(token);
    assert_string_equal(token, "4995f9b3");

    os_free(token);
}

void test_w_logtest_generate_token_success_empty_bytes(void ** state) {

    char * token = NULL;

    random_bytes_result = 5555; // 0x15_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    token = w_logtest_generate_token();

    assert_non_null(token);
    assert_string_equal(token, "000015b3");

    os_free(token);
}

/* w_logtest_get_rule_level */
void test_w_logtest_get_rule_level_empty_log(void ** state) {
    cJSON * log = NULL;
    int level;

    expect_string(__wrap__mdebug1, formatted_msg, "(7203): Empty log for check alert level");

    level = w_logtest_get_rule_level(log);

    assert_int_equal(level, 0);
}

void test_w_logtest_get_rule_level_empty_rule(void ** state) {
    cJSON * log = (cJSON *) 1;
    cJSON * rule = NULL;
    int level;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, rule);
    expect_string(__wrap__mdebug1, formatted_msg, "(7204): Output without rule");

    level = w_logtest_get_rule_level(log);

    assert_int_equal(level, 0);
}

void test_w_logtest_get_rule_level_empty_level(void ** state) {
    cJSON * json_log = (cJSON *) 1;
    cJSON * json_rule = (cJSON *) 1;
    cJSON * json_level = NULL;
    int level;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, json_rule);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, json_level);
    expect_string(__wrap__mdebug1, formatted_msg, "(7205): Rule without alert level");

    level = w_logtest_get_rule_level(json_log);

    assert_int_equal(level, 0);
}

void test_w_logtest_get_rule_level_ok(void ** state) {
    cJSON * json_log = (cJSON *) 1;
    cJSON * json_rule = (cJSON *) 1;
    cJSON * json_level;
    const int expect_level = 5;
    int ret_level;

    os_calloc(1, sizeof(cJSON), json_level);
    json_level->valueint = expect_level;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, json_rule);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, json_level);
    will_return(__wrap_cJSON_IsNumber, 1);

    ret_level = w_logtest_get_rule_level(json_log);

    assert_int_equal(ret_level, expect_level);

    os_free(json_level);
}

/* w_logtest_get_session */
void test_w_logtest_get_session_active(void ** state) {

    w_logtest_session_t active_session;
    w_logtest_session_t * ret_session;

    cJSON * json_request = (cJSON *) 1;
    cJSON * json_request_token;
    OSList * list_msg = (OSList *) 55;
    char * token = strdup("test_token");
    const time_t now = (time_t) 2020;

    os_calloc(1, sizeof(cJSON), json_request_token);
    json_request_token->valuestring = token;
    active_session.expired = false;
    active_session.last_connection = 0;


    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, json_request_token);

    expect_value(__wrap_OSHash_Get_ex, key, token);
    will_return(__wrap_OSHash_Get_ex, &active_session);

    will_return(__wrap_pthread_mutex_lock, 0);
    will_return(__wrap_time, now);
    will_return(__wrap_pthread_mutex_unlock, 0);

    ret_session = w_logtest_get_session(json_request, list_msg);

    assert_ptr_equal(ret_session, &active_session);
    assert_int_equal(now, ret_session->last_connection);

    os_free(token);
    os_free(json_request_token);
}

void test_w_logtest_get_session_expired_token(void ** state) {

    w_logtest_session_t * ret_session;

    cJSON * json_request = (cJSON *) 1;
    cJSON * json_request_token;
    OSList * list_msg = (OSList *) 55;
    char req_token[] = "test_token";

    os_calloc(1, sizeof(cJSON), json_request_token);
    json_request_token->valuestring = req_token;



    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, json_request_token);

    expect_string(__wrap_OSHash_Get_ex, key, "test_token");
    will_return(__wrap_OSHash_Get_ex, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "(7003): 'test_token' token expires.");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7003): 'test_token' token expires.");

    /* Generate token */
    random_bytes_result = 5555; // 0x00_00_15_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "000015b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    /* Initialize session*/
    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    char * cbd_file = "test.xml";
    Config.lists = calloc(2, sizeof(char *));
    Config.lists[0] = cbd_file;

    char * include_file = "test.xml";
    Config.includes = calloc(2, sizeof(char *));
    Config.includes[0] = include_file;

    will_return(__wrap_time, 1212);
    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 0);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 1);
    will_return(__wrap_AddHash_Rule, 0);

    /* Initialize session -- FTS init success */
    OSList * fts_list;
    OSHash * fts_store;
    OSList * list = (OSList *) 1;
    OSHash * hash = (OSHash *) 1;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, list);
    will_return(__wrap_OSList_SetMaxSize, 1);
    will_return(__wrap_OSHash_Create, hash);
    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);

    will_return(__wrap_Accumulate_Init, 1);


    expect_string(__wrap_OSHash_Add_ex, key, "000015b3");
    expect_not_value(__wrap_OSHash_Add_ex, data, NULL);
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7202): '000015b3' New token");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_INFO);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7202): '000015b3' New token");

    ret_session = w_logtest_get_session(json_request, list_msg);

    assert_non_null(ret_session);
    assert_false(ret_session->expired);
    assert_int_equal(ret_session->last_connection, 1212);

    os_free(ret_session->token);
    os_free(ret_session->eventlist);
    os_free(ret_session);
    os_free(Config.includes);
    os_free(Config.decoders);
    os_free(Config.lists);
    os_free(json_request_token);
}

void test_w_logtest_get_session_new(void ** state) {

    w_logtest_session_t * ret_session;

    cJSON * json_request = (cJSON *) 1;
    OSList * list_msg = (OSList *) 55;


    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    /* Generate token */
    random_bytes_result = 5555; // 0x00_00_15_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "000015b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    /* Initialize session*/
    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    char * cbd_file = "test.xml";
    Config.lists = calloc(2, sizeof(char *));
    Config.lists[0] = cbd_file;

    char * include_file = "test.xml";
    Config.includes = calloc(2, sizeof(char *));
    Config.includes[0] = include_file;

    will_return(__wrap_time, 1212);
    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 0);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 1);
    will_return(__wrap_AddHash_Rule, 0);

    /* Initialize session -- FTS init success */
    OSList * fts_list;
    OSHash * fts_store;
    OSList * list = (OSList *) 1;
    OSHash * hash = (OSHash *) 1;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, list);
    will_return(__wrap_OSList_SetMaxSize, 1);
    will_return(__wrap_OSHash_Create, hash);
    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);

    will_return(__wrap_Accumulate_Init, 1);


    expect_string(__wrap_OSHash_Add_ex, key, "000015b3");
    expect_not_value(__wrap_OSHash_Add_ex, data, NULL);
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7202): '000015b3' New token");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_INFO);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7202): '000015b3' New token");

    ret_session = w_logtest_get_session(json_request, list_msg);

    assert_non_null(ret_session);
    assert_false(ret_session->expired);
    assert_int_equal(ret_session->last_connection, 1212);

    os_free(ret_session->token);
    os_free(ret_session->eventlist);
    os_free(ret_session);
    os_free(Config.includes);
    os_free(Config.decoders);
    os_free(Config.lists);
}

void test_w_logtest_add_msg_response_null_list(void ** state) {
    cJSON * response;
    OSList * list_msg;
    int retval = 0;
    const int ret_expect = retval;

    will_return(__wrap_OSList_GetFirstNode, NULL);

    w_logtest_add_msg_response(response, list_msg, &retval);

    assert_int_equal(retval, ret_expect);

}

void test_w_logtest_add_msg_response_new_field_msg(void ** state) {
    cJSON * response = (cJSON*) 1;
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;
    const int ret_expect = W_LOGTEST_RCODE_ERROR_PROCESS;
    int retval = 999;

    cJSON * json_arr_msg = (cJSON*) 2;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_ERROR;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_CreateArray, (cJSON*) 1);

    expect_value(__wrap_cJSON_AddItemToObject, object, response);
    expect_string(__wrap_cJSON_AddItemToObject, string, "messages");

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    w_logtest_add_msg_response(response, list_msg, &retval);

    assert_int_equal(retval, ret_expect);
    os_free(list_msg);
}

void test_w_logtest_add_msg_response_error_msg(void ** state) {
    cJSON * response = (cJSON*) 1;
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;
    const int ret_expect = W_LOGTEST_RCODE_ERROR_PROCESS;
    int retval = 999;

    cJSON * json_arr_msg = (cJSON*) 2;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_ERROR;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 1);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    w_logtest_add_msg_response(response, list_msg, &retval);

    assert_int_equal(retval, ret_expect);
    os_free(list_msg);
}

void test_w_logtest_add_msg_response_warn_msg(void ** state) {
    cJSON * response = (cJSON*) 1;;
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;
    const int ret_expect = W_LOGTEST_RCODE_WARNING;
    int retval = W_LOGTEST_RCODE_SUCCESS;

    cJSON * json_arr_msg = (cJSON*) 2;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_WARNING;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 1);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "WARNING: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    w_logtest_add_msg_response(response, list_msg, &retval);

    assert_int_equal(retval, ret_expect);
    os_free(list_msg);
}

void test_w_logtest_add_msg_response_warn_dont_remplaze_error_msg(void ** state) {
    cJSON * response = (cJSON*) 1;
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;
    const int ret_expect = W_LOGTEST_RCODE_ERROR_PROCESS;
    int retval = W_LOGTEST_RCODE_ERROR_PROCESS;

    cJSON * json_arr_msg = (cJSON*) 2;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_WARNING;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 1);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "WARNING: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    w_logtest_add_msg_response(response, list_msg, &retval);

    assert_int_equal(retval, ret_expect);
    os_free(list_msg);
}

void test_w_logtest_add_msg_response_info_msg(void ** state) {
    cJSON * response = (cJSON*) 1;;
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;
    const int ret_expect = 999;
    int retval = ret_expect;

    cJSON * json_arr_msg = (cJSON*) 2;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_INFO;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 1);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "INFO: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    w_logtest_add_msg_response(response, list_msg, &retval);

    assert_int_equal(retval, ret_expect);
    os_free(list_msg);

}

/* w_logtest_check_input */
void test_w_logtest_check_input_malformed_json_long(void ** state) {

    char * input_raw_json = strdup("Test_input_json|_long<error>Test_i|nput_json_long");
    int pos_error = 25;
    char expect_slice_json[] = "|_long<error>Test_i|";

    bool retval;
    const bool ret_expect = false;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;

    cJSON_error_ptr = input_raw_json + pos_error;
    will_return(__wrap_cJSON_ParseWithOpts, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "(7306): Error parsing JSON");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7306): Error parsing JSON");

    expect_string(__wrap__mdebug1, formatted_msg, "(7307): Error in position 25, ... |_long<error>Test_i| ...");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(7307): Error in position 25, ... |_long<error>Test_i| ...");

    retval = w_logtest_check_input(input_raw_json, &request, list_msg);

    assert_int_equal(retval, ret_expect);

    os_free(input_raw_json);
}

void test_w_logtest_check_input_malformed_json_short(void ** state) {

    char * input_raw_json = strdup("json<err>json");
    int pos_error = 7;
    char expect_slice_json[] = "json<err>json";

    bool retval;
    const bool ret_expect = false;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;

    cJSON_error_ptr = input_raw_json + pos_error;
    will_return(__wrap_cJSON_ParseWithOpts, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "(7306): Error parsing JSON");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7306): Error parsing JSON");

    expect_string(__wrap__mdebug1, formatted_msg, "(7307): Error in position 7, ... json<err>json ...");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7307): Error in position 7, ... json<err>json ...");

    retval = w_logtest_check_input(input_raw_json, &request, list_msg);

    assert_int_equal(retval, ret_expect);

    os_free(input_raw_json);
}

void test_w_logtest_check_input_empty_json(void ** state) {

    char input_raw_json[] = "{}";

    bool retval;
    const bool ret_expect = false;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;

    will_return(__wrap_cJSON_ParseWithOpts, (OSList *) 1);

    /* location */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    expect_string(__wrap__mdebug1, formatted_msg, "(7308): 'location' JSON field is required and must be a string");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(7308): 'location' JSON field is required and must be a string");

    /* log_format */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    expect_string(__wrap__mdebug1, formatted_msg, "(7308): 'log_format' JSON field is required and must be a string");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(7308): 'log_format' JSON field is required and must be a string");

    /* event */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    expect_string(__wrap__mdebug1, formatted_msg, "(7308): 'event' JSON field is required and must be a string");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(7308): 'event' JSON field is required and must be a string");

    /* token */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    retval = w_logtest_check_input(input_raw_json, &request, list_msg);

    assert_int_equal(retval, ret_expect);
}

void test_w_logtest_check_input_missing_location(void ** state) {

    char input_raw_json[] = "{}";

    bool retval;
    const bool ret_expect = false;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;

    will_return(__wrap_cJSON_ParseWithOpts, (OSList *) 1);

    /* location */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    expect_string(__wrap__mdebug1, formatted_msg, "(7308): 'location' JSON field is required and must be a string");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(7308): 'location' JSON field is required and must be a string");

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    cJSON event = {0};
    event.valuestring = strdup("event str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &event);
    will_return(__wrap_cJSON_IsString, true);

    /* token */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    retval = w_logtest_check_input(input_raw_json, &request, list_msg);

    assert_int_equal(retval, ret_expect);
    
    os_free(event.valuestring);
    os_free(log_format.valuestring);
}

void test_w_logtest_check_input_missing_log_format(void ** state) {

    char input_raw_json[] = "{}";

    bool retval;
    const bool ret_expect = false;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;

    will_return(__wrap_cJSON_ParseWithOpts, (OSList *) 1);

    /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    expect_string(__wrap__mdebug1, formatted_msg, "(7308): 'log_format' JSON field is required and must be a string");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(7308): 'log_format' JSON field is required and must be a string");

    /* event */
    cJSON event = {0};
    event.valuestring = strdup("event str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &event);
    will_return(__wrap_cJSON_IsString, true);

    /* token */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    retval = w_logtest_check_input(input_raw_json, &request, list_msg);

    assert_int_equal(retval, ret_expect);
    os_free(event.valuestring);
    os_free(location.valuestring);
}

void test_w_logtest_check_input_missing_event(void ** state) {

    char input_raw_json[] = "{}";

    bool retval;
    const bool ret_expect = false;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;

    will_return(__wrap_cJSON_ParseWithOpts, (OSList *) 1);

    /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    expect_string(__wrap__mdebug1, formatted_msg, "(7308): 'event' JSON field is required and must be a string");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(7308): 'event' JSON field is required and must be a string");

    /* token */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    retval = w_logtest_check_input(input_raw_json, &request, list_msg);

    assert_int_equal(retval, ret_expect);
    os_free(location.valuestring);
    os_free(log_format.valuestring);
}

void test_w_logtest_check_input_full(void ** state) {

    char input_raw_json[] = "{}";

    bool retval;
    const bool ret_expect = true;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;

    will_return(__wrap_cJSON_ParseWithOpts, (OSList *) 1);

    /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    cJSON event = {0};
    event.valuestring = strdup("event str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &event);
    will_return(__wrap_cJSON_IsString, true);

    /* token */
    cJSON token = {0};
    token.valuestring = strdup("12345678");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);
    will_return(__wrap_cJSON_IsString, true);

    retval = w_logtest_check_input(input_raw_json, &request, list_msg);

    assert_int_equal(retval, ret_expect);

    os_free(location.valuestring);
    os_free(log_format.valuestring);
    os_free(event.valuestring);
    os_free(token.valuestring);
}

void test_w_logtest_check_input_full_empty_token(void ** state) {

    char input_raw_json[] = "{}";

    bool retval;
    const bool ret_expect = true;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;

    will_return(__wrap_cJSON_ParseWithOpts, (OSList *) 1);

   /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    cJSON event = {0};
    event.valuestring = strdup("event str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &event);
    will_return(__wrap_cJSON_IsString, true);

    /* token */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    retval = w_logtest_check_input(input_raw_json, &request, list_msg);

    assert_int_equal(retval, ret_expect);

    os_free(location.valuestring);
    os_free(log_format.valuestring);
    os_free(event.valuestring);
}

void test_w_logtest_check_input_bad_token_lenght(void ** state) {

    char input_raw_json[] = "{}";

    bool retval;
    const bool ret_expect = true;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;

    will_return(__wrap_cJSON_ParseWithOpts, (OSList *) 1);

   /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    cJSON event = {0};
    event.valuestring = strdup("event str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &event);
    will_return(__wrap_cJSON_IsString, true);

    /* token */
    cJSON token = {0};
    token.valuestring = strdup("1234");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);
    will_return(__wrap_cJSON_IsString, true);

    expect_string(__wrap__mdebug1, formatted_msg, "(7309): '1234' is not a valid token");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7309): '1234' is not a valid token");

    retval = w_logtest_check_input(input_raw_json, &request, list_msg);

    assert_int_equal(retval, ret_expect);
    os_free(location.valuestring);
    os_free(log_format.valuestring);
    os_free(event.valuestring);
    os_free(token.valuestring);
}

/* w_logtest_process_request */
void test_w_logtest_process_request_error_list(void ** state) {

    char raw_request[] = "Test request";
    char * retval;

    will_return(__wrap_OSList_Create, NULL);
    expect_string(__wrap__merror, formatted_msg, "(1290): Unable to create a new list (calloc).");

    retval = w_logtest_process_request(raw_request);

    assert_null(retval);

}

void test_w_logtest_process_request_error_check_imput(void ** state) {

    char raw_request[] = "Test request";
    char * retval;

    /* w_logtest_add_msg_response */
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_ERROR;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    /* w_logtest_process_request */
    will_return(__wrap_OSList_Create, list_msg);
    will_return(__wrap_OSList_SetMaxSize, 0);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 1);
    
    /* Error w_logtest_check_input */
    will_return(__wrap_cJSON_ParseWithOpts, (OSList *) 1);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    expect_string(__wrap__mdebug1, formatted_msg, "(7308): 'location' JSON field is required and must be a string");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(7308): 'location' JSON field is required and must be a string");
    
    cJSON log_format = {0};
    log_format.valuestring = strdup("log_foramat");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);
    
    cJSON event = {0};
    event.valuestring = strdup("event");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &event);
    will_return(__wrap_cJSON_IsString, true);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    /* w_logtest_process_request */

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 1);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 1);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    /* w_logtest_process_request */
    expect_string(__wrap_cJSON_AddNumberToObject, name, "codemsg");
    expect_value(__wrap_cJSON_AddNumberToObject, number, -2);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    will_return(__wrap_cJSON_PrintUnformatted, "{json response}");

    retval = w_logtest_process_request(raw_request);

    assert_string_equal(retval, "{json response}");
    os_free(event.valuestring);
    os_free(log_format.valuestring);

}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests w_logtest_init_parameters
        cmocka_unit_test(test_w_logtest_init_parameters_invalid),
        cmocka_unit_test(test_w_logtest_init_parameters_done),
        // Tests w_logtest_init
        cmocka_unit_test(test_w_logtest_init_error_parameters),
        cmocka_unit_test(test_w_logtest_init_logtest_disabled),
        cmocka_unit_test(test_w_logtest_init_conection_fail),
        cmocka_unit_test(test_w_logtest_init_OSHash_create_fail),
        // Tests w_logtest_fts_init
        cmocka_unit_test(test_w_logtest_fts_init_create_list_failure),
        cmocka_unit_test(test_w_logtest_fts_init_SetMaxSize_failure),
        cmocka_unit_test(test_w_logtest_fts_init_create_hash_failure),
        cmocka_unit_test(test_w_logtest_fts_init_setSize_failure),
        cmocka_unit_test(test_w_logtest_fts_init_success),
        // Tests w_logtest_remove_session
        cmocka_unit_test(test_w_logtest_remove_session_fail),
        cmocka_unit_test(test_w_logtest_remove_session_OK),
        // Tests w_logtest_check_inactive_sessions
        cmocka_unit_test(test_w_logtest_check_inactive_sessions_no_remove),
        cmocka_unit_test(test_w_logtest_check_inactive_sessions_remove),
        // Tests w_logtest_initialize_session
        cmocka_unit_test(test_w_logtest_initialize_session_error_decoders),
        cmocka_unit_test(test_w_logtest_initialize_session_error_cbd_list),
        cmocka_unit_test(test_w_logtest_initialize_session_error_rules),
        cmocka_unit_test(test_w_logtest_initialize_session_error_hash_rules),
        cmocka_unit_test(test_w_logtest_initialize_session_error_fts_init),
        cmocka_unit_test(test_w_logtest_initialize_session_error_accumulate_init),
        cmocka_unit_test(test_w_logtest_initialize_session_success),
        // Tests w_logtest_generate_token
        cmocka_unit_test(test_w_logtest_generate_token_success),
        cmocka_unit_test(test_w_logtest_generate_token_success_empty_bytes),
        // Tests w_logtest_get_rule_level
        cmocka_unit_test(test_w_logtest_get_rule_level_empty_log),
        cmocka_unit_test(test_w_logtest_get_rule_level_empty_rule),
        cmocka_unit_test(test_w_logtest_get_rule_level_empty_level),
        cmocka_unit_test(test_w_logtest_get_rule_level_ok),
        // Tests w_logtest_get_session
        cmocka_unit_test(test_w_logtest_get_session_active),
        cmocka_unit_test(test_w_logtest_get_session_expired_token),
        cmocka_unit_test(test_w_logtest_get_session_new),
        // Test w_logtest_add_msg_response
        cmocka_unit_test(test_w_logtest_add_msg_response_null_list),
        cmocka_unit_test(test_w_logtest_add_msg_response_new_field_msg),
        cmocka_unit_test(test_w_logtest_add_msg_response_error_msg),
        cmocka_unit_test(test_w_logtest_add_msg_response_warn_msg),
        cmocka_unit_test(test_w_logtest_add_msg_response_warn_dont_remplaze_error_msg),
        cmocka_unit_test(test_w_logtest_add_msg_response_info_msg),
        // Test w_logtest_check_input
        cmocka_unit_test(test_w_logtest_check_input_malformed_json_long),
        cmocka_unit_test(test_w_logtest_check_input_malformed_json_short),
        cmocka_unit_test(test_w_logtest_check_input_empty_json),
        cmocka_unit_test(test_w_logtest_check_input_missing_location),
        cmocka_unit_test(test_w_logtest_check_input_missing_log_format),
        cmocka_unit_test(test_w_logtest_check_input_missing_event),
        cmocka_unit_test(test_w_logtest_check_input_full_empty_token),
        cmocka_unit_test(test_w_logtest_check_input_full),
        cmocka_unit_test(test_w_logtest_check_input_bad_token_lenght),
        // Test w_logtest_process_request
        cmocka_unit_test(test_w_logtest_process_request_error_list),
        cmocka_unit_test(test_w_logtest_process_request_error_check_imput),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
