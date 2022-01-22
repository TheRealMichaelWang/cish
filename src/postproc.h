#pragma once

#ifndef POSTPROC_H
#define POSTPROC_H

typedef struct ast_parser ast_parser_t;

typedef enum postproc_gc_status {
	POSTPROC_GC_NONE,
	POSTPROC_GC_LOCAL_ALLOC,
	POSTPROC_GC_EXTERN_ALLOC,
	POSTPROC_GC_LOCAL_DYNAMIC,
	POSTPROC_GC_EXTERN_DYNAMIC,
} postproc_gc_status_t;

typedef enum postproc_trace_status {
	POSTPROC_TRACE_NONE,
	POSTPROC_TRACE_CHILDREN,
	POSTPROC_TRACE_DYNAMIC
} postproc_trace_status_t;

int ast_postproc(ast_parser_t* ast_parser);

#endif // !POSTPROC_H