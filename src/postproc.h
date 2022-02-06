#pragma once

#ifndef POSTPROC_H
#define POSTPROC_H

typedef struct ast_parser ast_parser_t;

typedef enum postproc_gc_status {
	POSTPROC_GC_LOCAL_ALLOC,
	POSTPROC_GC_UNKOWN_ALLOC,
	POSTPROC_GC_TRACED_ALLOC,
	POSTPROC_GC_SUPERTRACED_ALLOC,
	POSTPROC_GC_LOCAL_DYNAMIC,
	POSTPROC_GC_SUPEREXT_ALLOC,
	POSTPROC_GC_EXTERN_ALLOC,
	POSTPROC_GC_EXTERN_DYNAMIC,
	POSTPROC_GC_NONE,
} postproc_gc_status_t;

typedef enum postproc_free_status {
	POSTPROC_FREE_NONE,
	POSTPROC_FREE,
	POSTPROC_FREE_DYNAMIC
} postproc_free_status_t;

typedef enum postproc_trace_status {
	POSTPROC_TRACE_NONE,
	POSTPROC_TRACE_CHILDREN,
	POSTPROC_SUPERTRACE_CHILDREN,
	POSTPROC_TRACE_DYNAMIC
} postproc_trace_status_t;

typedef enum postproc_parent_status {
	POSTPROC_PARENT_IRRELEVANT,
	POSTPROC_PARENT_LOCAL,
	POSTPROC_PARENT_EXTERN,
	POSTPROC_PARENT_SUPEREXT
} postproc_parent_status_t;

int ast_postproc(ast_parser_t* ast_parser);

#endif // !POSTPROC_H