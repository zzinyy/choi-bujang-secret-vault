
CREATE OR REPLACE FUNCTION public.stage10_restore_note_atomic(
  p_note_id uuid,
  p_owner_id uuid,
  p_preview boolean DEFAULT false
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public', 'extensions'
AS $function$
DECLARE
  v_backup public.stage10_note_backups%ROWTYPE;
  v_check public.stage10_note_backups%ROWTYPE;
  v_current public.notes%ROWTYPE;
  v_restored public.notes%ROWTYPE;
  v_plan jsonb;
  v_result jsonb;
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtextextended(p_note_id::text, 0)
  );

  SELECT *
    INTO v_backup
  FROM public.stage10_note_backups
  WHERE note_id = p_note_id::text
    AND owner_id = p_owner_id
  ORDER BY created_at DESC, id DESC
  LIMIT 1;

  IF NOT FOUND THEN
    INSERT INTO public.stage10_policy_audit(action, outcome, details)
    VALUES (
      'note_restore',
      'fail',
      jsonb_build_object(
        'note_id', p_note_id,
        'owner_id', p_owner_id,
        'reason', 'backup_not_found'
      )
    );

    RETURN jsonb_build_object(
      'restored', false,
      'error', 'VERIFIED_NOTE_BACKUP_NOT_FOUND'
    );
  END IF;

  SELECT *
    INTO v_check
  FROM public.stage10_note_backups
  WHERE id = v_backup.id
    AND note_id = p_note_id::text
    AND owner_id = p_owner_id
  FOR SHARE;

  IF NOT FOUND
     OR v_check.created_at IS DISTINCT FROM v_backup.created_at
     OR v_check.title IS DISTINCT FROM v_backup.title
     OR v_check.content IS DISTINCT FROM v_backup.content
     OR v_check.content_sha256 IS DISTINCT FROM v_backup.content_sha256
     OR v_check.snapshot_sha256 IS DISTINCT FROM v_backup.snapshot_sha256
     OR v_check.content_sha256 IS DISTINCT FROM
        encode(digest(convert_to(v_check.content, 'UTF8'), 'sha256'), 'hex')
     OR v_check.snapshot_sha256 IS NULL
     OR v_check.snapshot_sha256 IS DISTINCT FROM
        encode(
          digest(
            convert_to(v_check.title || E'\n' || v_check.content, 'UTF8'),
            'sha256'
          ),
          'hex'
        )
  THEN
    INSERT INTO public.stage10_policy_audit(action, outcome, details)
    VALUES (
      'note_restore',
      'fail',
      jsonb_build_object(
        'note_id', p_note_id,
        'owner_id', p_owner_id,
        'backup_id', v_backup.id,
        'reason', 'backup_verification_failed'
      )
    );

    RETURN jsonb_build_object(
      'restored', false,
      'error', 'NOTE_BACKUP_VERIFICATION_FAILED'
    );
  END IF;

  SELECT *
    INTO v_current
  FROM public.notes
  WHERE id = p_note_id
  FOR UPDATE;

  IF FOUND AND v_current.owner_id IS DISTINCT FROM p_owner_id THEN
    INSERT INTO public.stage10_policy_audit(action, outcome, details)
    VALUES (
      'note_restore',
      'fail',
      jsonb_build_object(
        'note_id', p_note_id,
        'owner_id', p_owner_id,
        'reason', 'current_owner_mismatch'
      )
    );

    RETURN jsonb_build_object(
      'restored', false,
      'error', 'NOTE_OWNER_MISMATCH'
    );
  END IF;

  v_plan := jsonb_build_object(
    'backup_id', v_check.id,
    'backup_version', v_check.created_at,
    'current_exists', v_current.id IS NOT NULL,
    'changes', jsonb_build_object(
      'recreate', v_current.id IS NULL,
      'title', v_current.id IS NULL
        OR v_current.title IS DISTINCT FROM v_check.title,
      'content', v_current.id IS NULL
        OR v_current.content IS DISTINCT FROM v_check.content
    )
  );

  IF p_preview THEN
    RETURN jsonb_build_object(
      'preview', true,
      'verified', true,
      'backup_id', v_check.id,
      'backup_version', v_check.created_at,
      'plan', v_plan
    );
  END IF;

  INSERT INTO public.stage10_policy_audit(action, outcome, details)
  VALUES (
    'note_restore',
    'started',
    jsonb_build_object(
      'note_id', p_note_id,
      'owner_id', p_owner_id,
      'backup_id', v_check.id,
      'plan', v_plan
    )
  );

  INSERT INTO public.notes(id, owner_id, title, content)
  VALUES (
    p_note_id,
    p_owner_id,
    v_check.title,
    v_check.content
  )
  ON CONFLICT (id) DO UPDATE
    SET title = EXCLUDED.title,
        content = EXCLUDED.content
    WHERE public.notes.owner_id = p_owner_id
  RETURNING * INTO v_restored;

  IF v_restored.id IS NULL
     OR v_restored.owner_id IS DISTINCT FROM p_owner_id
     OR v_restored.title IS DISTINCT FROM v_check.title
     OR v_restored.content IS DISTINCT FROM v_check.content
  THEN
    RAISE EXCEPTION 'NOTE_RESTORE_VERIFICATION_FAILED';
  END IF;

  INSERT INTO public.stage10_policy_audit(action, outcome, details)
  VALUES (
    'note_restore',
    'pass',
    jsonb_build_object(
      'note_id', p_note_id,
      'owner_id', p_owner_id,
      'backup_id', v_check.id,
      'content_sha256', v_check.content_sha256
    )
  );

  v_result := jsonb_build_object(
    'restored', true,
    'id', v_restored.id,
    'owner_id', v_restored.owner_id,
    'backup_id', v_check.id,
    'backup_version', v_check.created_at,
    'content_sha256', v_check.content_sha256,
    'plan', v_plan
  );

  RETURN v_result;
END;
$function$;
