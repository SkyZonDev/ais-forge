class ApiError extends Error {
    public readonly statusCode: number;
    public readonly code: string;
    public readonly data: Record<string, unknown> | undefined;
    public readonly timestamp: string;

    constructor(
        message: string,
        statusCode: number = 500,
        code: string = 'INTERNAL_ERROR',
        data?: Record<string, unknown>
    ) {
        super(message);
        this.name = this.constructor.name;
        this.statusCode = statusCode;
        this.code = code;
        this.data = data;
        this.timestamp = new Date().toISOString();

        Error.captureStackTrace(this, this.constructor);
    }

    toJSON() {
        return {
            error: {
                name: this.name,
                message: this.message,
                code: this.code,
                statusCode: this.statusCode,
                timestamp: this.timestamp,
                ...(this.data && { data: this.data }),
                ...(process.env.NODE_ENV === 'development' && {
                    stack: this.stack,
                }),
            },
        };
    }
}

export { ApiError };
