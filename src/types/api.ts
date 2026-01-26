// ============================================
// Types de base
// ============================================

export interface PaginationMeta {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
}

export interface ValidationError {
    code: string;
    field?: string | null;
    message: string;
}

// ============================================
// Structure de réponse unifiée
// ============================================

// Base commune à toutes les réponses
interface BaseResponse {
    timestamp: string;
}

// Réponse succès (avec data)
export interface SuccessResponse<T, M = Record<string, unknown>>
    extends BaseResponse {
    success: true;
    message: string;
    data: T;
    meta?: M;
}

// Réponse succès paginée (meta obligatoire avec pagination)
export interface PaginatedResponse<T> extends BaseResponse {
    success: true;
    message: string;
    data: T[];
    meta: PaginationMeta & Record<string, unknown>;
}

// Réponse erreur
export interface ErrorResponse extends BaseResponse {
    success: false;
    message: string;
    code: string;
    errors?: ValidationError[];
    details?: Record<string, unknown>;
    stack?: string; // Uniquement en dev
}

// ============================================
// Union discriminée pour le frontend
// ============================================

export type ApiResponse<T = {}, M = Record<string, unknown>> =
    | SuccessResponse<T, M>
    | ErrorResponse;

export type ApiPaginatedResponse<T> = PaginatedResponse<T> | ErrorResponse;
