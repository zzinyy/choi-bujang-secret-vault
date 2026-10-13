
/**
 * Stage 8: Verify instructor authorization.
 *
 * The caller must first verify the user's login token.
 * Never trust role, userId, or isInstructor from request.body.
 *
 * Fail closed: errors or missing membership return false.
 */

export async function verifyInstructor(supabase, login) {
  // Require a previously verified student login.
  // Judge identities are not automatically instructors.
  if (
    !login ||
    login.kind !== 'student' ||
    typeof login.userId !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(login.userId)
  ) {
    return false;
  }

  // Require a server-side Supabase client.
  if (!supabase || typeof supabase.from !== 'function') {
    return false;
  }

  try {
    const { data, error } = await supabase
      .from('instructor_roles')
      .select('user_id')
      .eq('user_id', login.userId)
      .maybeSingle();

    if (error || !data) {
      return false;
    }

    return data.user_id === login.userId;
  } catch {
    return false;
  }
}
