import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

// Canonical shadcn/ui `cn` helper — composes conditional class
// names and resolves Tailwind utility conflicts in the output. Use
// everywhere classes are conditionally combined so "bg-red-500" on
// a variant never fights "bg-blue-500" from a default.
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
