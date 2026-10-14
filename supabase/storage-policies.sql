-- Reglas de Supabase Storage para los archivos cifrados de Aeterna.
-- Correr en Supabase: SQL Editor -> New query -> pegar -> Run.
--
-- La app ya no habla con Supabase: sube y baja todo a traves del servidor de Render, que usa la llave secreta
-- (a esa no le aplican estas reglas). Por eso los buckets "videos" y "voices" son privados y no hay ninguna regla
-- para "anon" ni "authenticated": nadie fuera del servidor puede listar, subir, bajar ni borrar archivos.

-- Reglas de versiones anteriores de la app (dejaban subir archivos con la llave publica)
drop policy if exists "Allow uploads to videos bucket" on storage.objects;
drop policy if exists "Allow uploads to voices bucket 1lm9pxd_0" on storage.objects;
drop policy if exists "aeterna_insert_only" on storage.objects;

-- Buckets privados y limite de tamano por archivo (50 MB)
update storage.buckets set public = false, file_size_limit = 52428800 where id in ('videos', 'voices');
