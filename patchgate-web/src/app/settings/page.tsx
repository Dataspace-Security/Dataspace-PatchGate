import { redirect } from "next/navigation";

/** /settings → the first settings tab. */
export default function SettingsIndex(): never {
  redirect("/settings/rings");
}
