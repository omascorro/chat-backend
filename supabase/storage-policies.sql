-- Reglas de Supabase Storage para los archivos cifrados de Aeterna.
-- Correr en Supabase: SQL Editor -> New query -> pegar -> Run.
--
-- Antes de correrlo: en Storage -> Policies, borra cualquier politica de los buckets "videos" y "voices"
-- que permita SELECT, UPDATE o DELETE a "anon" o "public". La app solo necesita SUBIR archivos nuevos;
-- la descarga usa la URL publica del bucket y el borrado lo hace el servidor con la service role key.

-- Reglas de la version anterior de la app (dejaban subir cualquier nombre a cualquiera)
drop policy if exists "Allow uploads to videos bucket" on storage.objects;
drop policy if exists "Allow uploads to voices bucket 1lm9pxd_0" on storage.objects;

-- La app (llave anon) solo puede subir archivos nuevos, con el nombre aleatorio que genera la app.
-- Sin politicas de SELECT/UPDATE/DELETE nadie puede listar los archivos, sobrescribirlos ni borrarlos.
drop policy if exists "aeterna_insert_only" on storage.objects;
create policy "aeterna_insert_only" on storage.objects
  for insert to anon
  with check (
    bucket_id in ('videos', 'voices')
    and name ~ '^[a-f0-9]{32}\.bin$'
  );

-- Limite de tamano por archivo (50 MB) para que nadie use el bucket como disco gratis
update storage.buckets set file_size_limit = 52428800 where id in ('videos', 'voices');
