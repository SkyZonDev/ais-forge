import { z } from 'zod';

const password = z
    .string()
    .min(8, 'Le mot de passe doit contenir au moins 8 caractères')
    .max(128, 'Le mot de passe ne doit pas dépasser 128 caractères.')
    .regex(/[A-Z]/, 'Le mot de passe doit contenir au moins une majuscule.')
    .regex(/[a-z]/, 'Le mot de passe doit contenir au moins une minuscule.')
    .regex(/[0-9]/, 'Le mot de passe doit contenir au moins un chiffre.')
    .regex(
        /[!@#$%^&*(),.?":{}|<>]/,
        'Le mot de passe doit contenir au moins un caractère spécial.'
    );

export const schema = {
    signin: {
        body: z.object({
            email: z
                .string()
                .min(1, "L'identifiant est requis")
                .refine((value) => {
                    // Vérifier si c'est un email valide
                    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                    if (emailRegex.test(value)) {
                        return true;
                    }
                    // Sinon, vérifier si c'est un nom d'utilisateur valide (alphanumérique, min 3 caractères)
                    const usernameRegex = /^[a-z][a-z0-9_]*$/;
                    return usernameRegex.test(value);
                }, "L'identifiant doit être un email valide ou un nom d'utilisateur (alphanumérique, min 3 caractères)"),
            password,
            rememberMe: z.boolean(),
        }),
    },
    signup: {
        body: z.object({
            firstName: z.string().min(1, 'Le prénom est requis'),
            lastName: z.string().min(1, 'Le nom est requis'),
            email: z.email("L'email est requis"),
            password,
            organizationName: z
                .string("Le nom de l'organisation est requis")
                .min(3, 'Le nom doit faire au moins 3 caractères')
                .max(255, 'Le nom ne peut pas dépasser 255 caractères')
                .trim(),
            organizationSlug: z
                .string("Le slug de l'organisation est requis")
                .min(3, 'Le slug doit faire au moins 3 caractères')
                .max(100, 'Le slug ne peut pas dépasser 100 caractères')
                .regex(
                    /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
                    'Le slug doit contenir uniquement des lettres minuscules, chiffres et tirets'
                )
                .trim(),
        }),
    },
    refresh: {
        body: z.object({
            refreshToken: z.string(),
        }),
    },
};
