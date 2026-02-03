import js from '@eslint/js';
import globals from 'globals';
import prettierConfig from 'eslint-config-prettier';

export default [
	js.configs.recommended,
	prettierConfig,
	{
		languageOptions: {
			ecmaVersion: 2022,
			sourceType: 'module',
			globals: {
				...globals.browser,
				...globals.node,
				...globals.es2021,
			},
		},
		rules: {
			// Customize rules as needed
			'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
			'no-console': 'off',
			'prefer-const': 'error',
			'no-var': 'error',
		},
	},
	{
		ignores: ['node_modules/**', '.wrangler/**', 'dist/**', 'build/**', 'coverage/**'],
	},
];
