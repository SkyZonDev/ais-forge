import type { FastifyReply } from 'fastify';
import { ZodError } from 'zod';
import type {
    ErrorResponse,
    PaginatedResponse,
    PaginationMeta,
    SuccessResponse,
    ValidationError,
} from '../../types/api';
import { ApiError } from './api-error';

export interface ResponseOptions<M = Record<string, unknown>> {
    meta?: M;
    headers?: Record<string, string | string[]>;
}

export class ApiResponse {
    /**
     * Sends a successful response with data.
     *
     * @param reply - The Fastify reply object
     * @param data - The response data payload
     * @param message - Success message (default: "Success")
     * @param options - Optional metadata and headers
     * @returns FastifyReply with status 200
     */
    static success<T, M = Record<string, unknown>>(
        reply: FastifyReply,
        data: T,
        message = 'Success',
        options: ResponseOptions<M> = {}
    ): FastifyReply {
        const { meta, headers = {} } = options;

        this.setHeaders(reply, headers);

        const response: SuccessResponse<T, M> = {
            success: true,
            message,
            data,
            ...(meta && { meta }),
            timestamp: new Date().toISOString(),
        };

        return reply.status(200).send(response);
    }

    /**
     * Sends a resource creation success response.
     *
     * @param reply - The Fastify reply object
     * @param data - The created resource data
     * @param message - Success message (default: "Resource created successfully")
     * @param options - Optional metadata and headers
     * @returns FastifyReply with status 201
     */
    static created<T, M = Record<string, unknown>>(
        reply: FastifyReply,
        data: T,
        message = 'Resource created successfully',
        options: ResponseOptions<M> = {}
    ): FastifyReply {
        const { meta, headers = {} } = options;

        this.setHeaders(reply, headers);

        const response: SuccessResponse<T, M> = {
            success: true,
            message,
            data,
            ...(meta && { meta }),
            timestamp: new Date().toISOString(),
        };

        return reply.status(201).send(response);
    }

    /**
     * Sends a no content response.
     *
     * @param reply - The Fastify reply object
     * @returns FastifyReply with status 204 and no body
     */
    static noContent(reply: FastifyReply) {
        return reply.status(204).send();
    }

    /**
     * Sends a paginated response with metadata.
     *
     * @param reply - The Fastify reply object
     * @param data - Array of paginated items
     * @param pagination - Pagination metadata (page, limit, total)
     * @param message - Success message (default: "Success")
     * @param options - Optional additional metadata and headers
     * @returns FastifyReply with status 200 and pagination metadata
     */
    static paginated<T>(
        reply: FastifyReply,
        data: T[],
        pagination: Omit<PaginationMeta, 'totalPages'>,
        message = 'Success',
        options: ResponseOptions = {}
    ): FastifyReply {
        const { meta = {}, headers = {} } = options;

        this.setHeaders(reply, headers);

        const paginationMeta: PaginationMeta = {
            page: pagination.page,
            limit: pagination.limit,
            total: pagination.total,
            totalPages: Math.ceil(pagination.total / pagination.limit) || 0,
        };

        const response: PaginatedResponse<T> = {
            success: true,
            message,
            data,
            meta: { ...paginationMeta, ...meta },
            timestamp: new Date().toISOString(),
        };

        return reply.status(200).send(response);
    }

    /**
     * Sends a generic error response.
     *
     * @param reply - The Fastify reply object
     * @param options - Error configuration (message, status code, error code, validation errors, details)
     * @returns FastifyReply with the specified error status code
     */
    static error(
        reply: FastifyReply,
        options: {
            message: string;
            statusCode?: number;
            code?: string;
            errors?: ValidationError[];
            details?: Record<string, unknown>;
        }
    ): FastifyReply {
        const {
            message,
            statusCode = 400,
            code = 'UNEXPECTED_ERROR',
            errors,
            details,
        } = options;

        const response: ErrorResponse = {
            success: false,
            message,
            code,
            ...(errors && { errors }),
            ...(details && { details }),
            timestamp: new Date().toISOString(),
        };

        return reply.status(statusCode).send(response);
    }

    /**
     * Sends a bad request error response.
     *
     * @param reply - The Fastify reply object
     * @param message - Error message (default: "Invalid request")
     * @param code - Error code (default: "BAD_REQUEST")
     * @param errors - Optional validation errors array
     * @returns FastifyReply with status 400
     */
    static badRequest(
        reply: FastifyReply,
        message = 'Invalid request',
        code = 'BAD_REQUEST',
        errors?: ValidationError[]
    ) {
        return this.error(reply, {
            message,
            statusCode: 400,
            code,
            errors,
        });
    }

    /**
     * Sends an unauthorized error response.
     *
     * @param reply - The Fastify reply object
     * @param message - Error message (default: "Unauthorized")
     * @param code - Error code (default: "UNAUTHORIZED")
     * @returns FastifyReply with status 401
     */
    static unauthorized(
        reply: FastifyReply,
        message = 'Unauthorized',
        code = 'UNAUTHORIZED'
    ) {
        return this.error(reply, {
            message,
            statusCode: 401,
            code,
        });
    }

    /**
     * Sends a forbidden error response.
     *
     * @param reply - The Fastify reply object
     * @param message - Error message (default: "Access forbidden")
     * @param code - Error code (default: "FORBIDDEN")
     * @returns FastifyReply with status 403
     */
    static forbidden(
        reply: FastifyReply,
        message = 'Access forbidden',
        code = 'FORBIDDEN'
    ): FastifyReply {
        return this.error(reply, {
            message,
            statusCode: 403,
            code,
        });
    }

    /**
     * Sends a not found error response.
     *
     * @param reply - The Fastify reply object
     * @param message - Error message (default: "Resource not found")
     * @param code - Error code (default: "NOT_FOUND")
     * @returns FastifyReply with status 404
     */
    static notFound(
        reply: FastifyReply,
        message = 'Resource not found',
        code = 'NOT_FOUND'
    ): FastifyReply {
        return this.error(reply, {
            message,
            statusCode: 404,
            code,
        });
    }

    /**
     * Sends a conflict error response.
     *
     * @param reply - The Fastify reply object
     * @param message - Error message (default: "Resource conflict")
     * @param code - Error code (default: "CONFLICT")
     * @param details - Optional additional error details
     * @returns FastifyReply with status 409
     */
    static conflict(
        reply: FastifyReply,
        message = 'Resource conflict',
        code = 'CONFLICT',
        details?: Record<string, unknown>
    ): FastifyReply {
        return this.error(reply, {
            message,
            statusCode: 409,
            code,
            details,
        });
    }

    /**
     * Sends a validation error response.
     *
     * @param reply - The Fastify reply object
     * @param errors - Array of validation errors with field and message details
     * @param message - Error message (default: "Validation error")
     * @param code - Error code (default: "VALIDATION_ERROR")
     * @returns FastifyReply with status 422
     */
    static validationError(
        reply: FastifyReply,
        errors: ValidationError[],
        message = 'Validation error',
        code = 'VALIDATION_ERROR'
    ): FastifyReply {
        return this.error(reply, {
            message,
            statusCode: 422,
            code,
            errors,
        });
    }

    /**
     * Sends a redirect response.
     *
     * @param reply - The Fastify reply object
     * @param url - The URL to redirect to
     * @returns FastifyReply with status 302 and redirect URL
     */
    static redirect(reply: FastifyReply, url: string) {
        return reply.status(302).send({
            success: true,
            message: 'redirect',
            data: { url },
            timestamp: new Date().toISOString(),
        });
    }

    /**
     * Sends an internal server error response.
     *
     * @param reply - The Fastify reply object
     * @param message - Error message (default: "Internal server error")
     * @param code - Error code (default: "INTERNAL_ERROR")
     * @returns FastifyReply with status 500
     */
    static internalError(
        reply: FastifyReply,
        message = 'Internal server error',
        code = 'INTERNAL_ERROR'
    ): FastifyReply {
        return this.error(reply, {
            message,
            statusCode: 500,
            code,
        });
    }

    /**
     * Converts an ApiError instance into a formatted error response.
     *
     * @param reply - The Fastify reply object
     * @param error - The ApiError instance to convert
     * @returns FastifyReply with the error's status code and formatted response
     */
    static fromApiError(reply: FastifyReply, error: ApiError) {
        return reply.status(error.statusCode).send({
            success: false,
            message: error.message,
            code: error.code,
            ...(error.data && { data: error.data }),
            timestamp: error.timestamp,
            ...(process.env.NODE_ENV === 'development' && {
                stack: error.stack,
            }),
        });
    }

    /**
     * Converts a Zod validation error into a formatted validation error response.
     *
     * @param reply - The Fastify reply object
     * @param error - The ZodError instance containing validation issues
     * @returns FastifyReply with status 422 and formatted validation errors
     */
    static fromZodError(reply: FastifyReply, error: ZodError) {
        const validationErrors: ValidationError[] = error.issues.map((err) => ({
            code: err.code,
            field: err.path.join('.'),
            message: err.message,
        }));
        console.log(error.issues);

        return this.validationError(
            reply,
            validationErrors,
            'Erreur de validation'
        );
    }

    /**
     * Universal error handler that routes different error types to appropriate response methods.
     *
     * @param reply - The Fastify reply object
     * @param error - The error to handle (ApiError, ZodError, Error, or unknown)
     * @returns FastifyReply with appropriate error response based on error type
     */
    static handleError(reply: FastifyReply, error: unknown) {
        if (error instanceof ApiError) {
            return this.fromApiError(reply, error);
        }

        if (error instanceof ZodError) {
            return this.fromZodError(reply, error);
        }

        if (error instanceof Error) {
            return this.internalError(reply, error.message);
        }

        return this.internalError(
            reply,
            "Une erreur inattendue s'est produite"
        );
    }

    // ============================================
    // Utilities
    // ============================================

    /**
     * Sets custom headers on the Fastify reply object.
     * Handles both single values and arrays (e.g., for Set-Cookie headers).
     *
     * @param reply - The Fastify reply object
     * @param headers - Record of header names to their values
     */
    private static setHeaders(
        reply: FastifyReply,
        headers: Record<string, string | string[]>
    ): void {
        Object.entries(headers).forEach(([key, value]) => {
            if (key.toLowerCase() === 'set-cookie' && Array.isArray(value)) {
                value.forEach((cookie) => reply.header(key, cookie));
            } else {
                reply.header(key, value as string);
            }
        });
    }
}
